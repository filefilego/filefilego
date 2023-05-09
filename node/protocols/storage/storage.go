package storage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

const (
	// ProtocolID represents the response protocol id and version.
	ProtocolID = "/ffg/storagequery_response/1.0.0"
	// SpeedTestProtocolID is a speed test protocol id and version.
	SpeedTestProtocolID = "/ffg/storage_speed/1.0.0"
	// FileUploadProtocolID is a file upload protocol id and version.
	FileUploadProtocolID = "/ffg/storage_upload/1.0.0"

	bufferSize = 8192
)

// Interface represents a set of functionalities by the storage query.
type Interface interface {
	SendStorageQueryResponse(ctx context.Context, peerID peer.ID, payload *messages.StorageQueryResponseProto) error
	GetDiscoveredStorageProviders() []*messages.StorageQueryResponseProto
	TestSpeedWithRemotePeer(ctx context.Context, peerID peer.ID, fileSize uint64) (time.Duration, error)
}

// Protocol wraps the storage protocols and handlers.
type Protocol struct {
	host             host.Host
	storageProviders map[string]*messages.StorageQueryResponseProto
	storagePublic    bool
	mu               sync.RWMutex
}

// New creates a storage protocol.
func New(h host.Host, storagePublic bool) (*Protocol, error) {
	if h == nil {
		return nil, errors.New("host is nil")
	}
	p := &Protocol{
		host:             h,
		storageProviders: make(map[string]*messages.StorageQueryResponseProto),
		storagePublic:    storagePublic,
	}

	// all types of nodes listen for this protocol
	// its a callback when a storage providers wants to communicate back to the node which
	// requested storage discovery.
	p.host.SetStreamHandler(ProtocolID, p.handleIncomingStorageQueryResponse)
	if p.storagePublic {
		p.host.SetStreamHandler(FileUploadProtocolID, p.handleIncomingFileUpload)
		p.host.SetStreamHandler(SpeedTestProtocolID, p.handleIncomingSpeedTest)
	}

	return p, nil
}

// handleIncomingFileUpload handles incoming file uploads from other nodes.
func (p *Protocol) handleIncomingFileUpload(s network.Stream) {}

// handleIncomingSpeedTest handles incoming speed tests.
func (p *Protocol) handleIncomingSpeedTest(s network.Stream) {
	c := bufio.NewReader(s)
	defer s.Close()

	// read the first 8 bytes to determine the amount of the data requested
	fileSizeBytes := make([]byte, 8)
	_, err := c.Read(fileSizeBytes)
	if err != nil {
		log.Errorf("failed to read from handleIncomingSpeedTest stream: %v", err)
		return
	}

	fileSize := int(binary.LittleEndian.Uint64(fileSizeBytes))
	if fileSize > common.MB*10 {
		log.Errorf("requested speed test file is larger than 10 MB in handleIncomingSpeedTest stream: %v", err)
		return
	}

	totalSent := 0
	buf := make([]byte, bufferSize)
	for totalSent < fileSize {
		n, err := rand.Read(buf)
		if err != nil {
			return
		}
		diff := fileSize - totalSent
		if diff < n {
			n = diff
		}

		_, err = s.Write(buf[:n])
		if err != nil {
			log.Errorf("failed to write random bytes to stream in handleIncomingSpeedTest stream: %v", err)
			return
		}
	}
}

// TestSpeedWithRemotePeer performs a speed test with a remote node.
func (p *Protocol) TestSpeedWithRemotePeer(ctx context.Context, peerID peer.ID, fileSize uint64) (time.Duration, error) {
	s, err := p.host.NewStream(ctx, peerID, SpeedTestProtocolID)
	if err != nil {
		return 0, fmt.Errorf("failed to connect to peer for sending data query response: %w", err)
	}
	defer s.Close()

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, fileSize)

	n, err := s.Write(buf)
	if err != nil {
		return 0, fmt.Errorf("failed to write to stream: %w", err)
	}

	if n != len(buf) {
		return 0, errors.New("failed to wrtie file size request to stream")
	}

	start := time.Now()
	readBuf := make([]byte, bufferSize)
	for {
		_, err := s.Read(readBuf)
		if err == io.EOF {
			break
		}

		if err != nil {
			break
		}
	}
	elapsed := time.Since(start)

	return elapsed, nil
}

// handleIncomingStorageQueryResponse handles incoming storage query responses from storage provider nodes.
func (p *Protocol) handleIncomingStorageQueryResponse(s network.Stream) {
	buf, err := io.ReadAll(s)
	defer s.Close()
	if err != nil {
		log.Warnf("failed to read data from stream: %v", err)
		return
	}

	tmp := messages.StorageQueryResponseProto{}
	err = proto.Unmarshal(buf, &tmp)
	if err != nil {
		log.Warnf("failed to unmarshal data query response: %v", err)
		return
	}

	publicKeyStorageProvider, err := crypto.PublicKeyFromBytes(tmp.PublicKey)
	if err != nil {
		log.Warnf("failed to get public key from data query response: %v", err)
		return
	}

	data := bytes.Join(
		[][]byte{
			[]byte(tmp.StorageProviderPeerAddr),
			[]byte(tmp.Location),
			[]byte(tmp.FeesPerByte),
			tmp.PublicKey,
		},
		[]byte{},
	)

	h := sha256.New()
	if _, err := h.Write(data); err != nil {
		log.Errorf("failed to hash the storage query response: %v", err)
		return
	}
	hash := h.Sum(nil)
	if !bytes.Equal(hash, tmp.Hash) {
		log.Error("storage query hashes don't match")
		return
	}

	ok, err := publicKeyStorageProvider.Verify(hash, tmp.Signature)
	if err != nil || !ok {
		log.Error("failed to verify storage query response")
	}

	p.mu.Lock()
	p.storageProviders[tmp.StorageProviderPeerAddr] = &tmp
	p.mu.Unlock()
}

// GetDiscoveredStorageProviders returns a list of discovered storage providers.
func (p *Protocol) GetDiscoveredStorageProviders() []*messages.StorageQueryResponseProto {
	p.mu.RLock()
	defer p.mu.RUnlock()
	providers := make([]*messages.StorageQueryResponseProto, 0)
	for _, v := range p.storageProviders {
		providers = append(providers, v)
	}

	return providers
}

// SendStorageQueryResponse sends back the storage query response to initiator.
func (p *Protocol) SendStorageQueryResponse(ctx context.Context, peerID peer.ID, payload *messages.StorageQueryResponseProto) error {
	s, err := p.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return fmt.Errorf("failed to connect to peer for sending data query response: %w", err)
	}
	defer s.Close()

	bts, err := proto.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	n, err := s.Write(bts)
	if err != nil {
		// nolint:errcheck
		s.Reset()
		return fmt.Errorf("failed to write to stream: %w", err)
	}

	if len(bts) != n {
		return errors.New("amount of data written to the stream do not match the payload size")
	}

	return nil
}
