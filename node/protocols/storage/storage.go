package storage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/multiformats/go-multiaddr"
	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/filefilego/filefilego/storage"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

const (
	// ProtocolID represents the response protocol id and version.
	ProtocolID = "/ffg/storagequery_response/1.0.0"
	// DiscoveredPeersProtocolID is a discovered peer protocol id and version.
	DiscoveredPeersProtocolID = "/ffg/disc_peers/1.0.0"
	// SpeedTestProtocolID is a speed test protocol id and version.
	SpeedTestProtocolID = "/ffg/storage_speed/1.0.0"
	// FileUploadProtocolID is a file upload protocol id and version.
	FileUploadProtocolID = "/ffg/storage_upload/1.0.0"
	// StorageCapabilitiesProtocolID is a protocol to indicate the capabilities of a storage node.
	StorageCapabilitiesProtocolID = "/ffg/storage_cap/1.0.0"

	bufferSize = 8192
)

// Interface represents a set of functionalities by the storage query.
type Interface interface {
	SendStorageQueryResponse(ctx context.Context, peerID peer.ID, payload *messages.StorageQueryResponseProto) error
	GetDiscoveredStorageProviders() []ProviderWithCountry
	TestSpeedWithRemotePeer(ctx context.Context, peerID peer.ID, fileSize uint64) (time.Duration, error)
	UploadFileWithMetadata(ctx context.Context, peerID peer.ID, filePath string, publicKeyOwner []byte, feesPerByte string) (storage.FileMetadata, error)
	GetUploadProgress(peerID peer.ID, filePath string) (int, string, error)
	SetUploadingStatus(peerID peer.ID, filePath, fileHash string, err error)
	SetCancelFileUpload(peerID peer.ID, filePath string, cancelled bool, cancel context.CancelFunc)
	GetCancelFileUploadStatus(peerID peer.ID, filePath string) (bool, context.CancelFunc)
	ResetProgressAndCancelStatus(peerID peer.ID, filePath string)
	SendDiscoveredStorageTransferRequest(ctx context.Context, peerID peer.ID) (int, error)
	GetStorageCapabilities(ctx context.Context, peerID peer.ID) (*messages.StorageCapabilitiesProto, error)
}

// GeoIPLocator given an ip address it returns the country info.
type GeoIPLocator interface {
	Country(ipAddress net.IP) (*geoip2.Country, error)
}

type uploadStatus struct {
	err      error
	fileHash string
}

// ProviderWithCountry contain the response and the country if available.
type ProviderWithCountry struct {
	Country  *geoip2.Country                     `json:"country"`
	Response *messages.StorageQueryResponseProto `json:"response"`
}

type cancelUploadItem struct {
	cancelFunc context.CancelFunc
	cancelled  bool
}

// Protocol wraps the storage protocols and handlers.
type Protocol struct {
	host                host.Host
	storageProviders    map[string]ProviderWithCountry
	storagePublic       bool
	storage             storage.Interface
	ipLocator           GeoIPLocator
	uploadProgress      map[string]int
	uploadStatus        map[string]uploadStatus
	cancelUploads       map[string]cancelUploadItem
	uptime              int64
	allowFeesOverride   bool
	feesPerByte         string
	showStorageCapacity bool
	mu                  sync.RWMutex
}

// New creates a storage protocol.
func New(h host.Host, storage storage.Interface, ipLocator GeoIPLocator, storagePublic bool, uptime int64, allowFeesOverride bool, feesPerByte string, showStorageCapacity bool) (*Protocol, error) {
	if h == nil {
		return nil, errors.New("host is nil")
	}

	if storage == nil {
		return nil, errors.New("storage is nil")
	}
	storage.StoragePath()

	if ipLocator == nil {
		ipLocator = &defaultIPLocator{}
	}

	p := &Protocol{
		host:                h,
		storage:             storage,
		ipLocator:           ipLocator,
		storagePublic:       storagePublic,
		storageProviders:    make(map[string]ProviderWithCountry),
		uploadProgress:      make(map[string]int),
		uploadStatus:        make(map[string]uploadStatus),
		cancelUploads:       make(map[string]cancelUploadItem),
		uptime:              uptime,
		allowFeesOverride:   allowFeesOverride,
		feesPerByte:         feesPerByte,
		showStorageCapacity: showStorageCapacity,
	}

	// all types of nodes listen for this protocol
	// its a callback when a storage providers wants to communicate back to the node which
	// requested storage discovery.
	p.host.SetStreamHandler(ProtocolID, p.handleIncomingStorageQueryResponse)
	p.host.SetStreamHandler(DiscoveredPeersProtocolID, p.handleIncomingDiscoveredStorageTransfer)

	if p.storagePublic {
		p.host.SetStreamHandler(FileUploadProtocolID, p.HandleIncomingFileUploads)
		p.host.SetStreamHandler(SpeedTestProtocolID, p.handleIncomingSpeedTest)
		p.host.SetStreamHandler(StorageCapabilitiesProtocolID, p.handleIncomingStorageCapabilityRequest)
	}

	return p, nil
}

// handleIncomingStorageCapabilityRequest is responsible
func (p *Protocol) handleIncomingStorageCapabilityRequest(s network.Stream) {
	defer s.Close()
	var err error
	storageDirCapacity := uint64(0)
	if p.showStorageCapacity {
		storageDirCapacity, err = common.GetDirectoryFreeSpace(p.storage.StoragePath())
		if err != nil {
			log.Warnf("failed to get storage capacity: %v", err)
		}
	}

	capabilities := messages.StorageCapabilitiesProto{
		AllowFeesOverride: p.allowFeesOverride,
		FeesPerByte:       p.feesPerByte,
		StorageCapacity:   storageDirCapacity,

		Platform: runtime.GOOS,
		Uptime:   time.Now().Unix() - p.uptime,
	}

	data, err := proto.Marshal(&capabilities)
	if err != nil {
		log.Warnf("failed to marshal storage capability payload: %v", err)
		return
	}
	_, err = s.Write(data)
	if err != nil {
		log.Warnf("failed to write storage capability payload to stream: %v", err)
	}
}

// GetStorageCapabilities sends a request to remote peer to get its storage capabilities.
func (p *Protocol) GetStorageCapabilities(ctx context.Context, peerID peer.ID) (*messages.StorageCapabilitiesProto, error) {
	s, err := p.host.NewStream(ctx, peerID, StorageCapabilitiesProtocolID)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to peer for sending storage capability request: %w", err)
	}
	defer s.Close()

	maxBytes := int64(10 * common.KB)
	limitReader := io.LimitReader(s, maxBytes)
	buffer, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read storage capability data from stream: %w", err)
	}

	if len(buffer) == 0 {
		return nil, errors.New("failed to read data from stream")
	}

	capabilities := messages.StorageCapabilitiesProto{}
	err = proto.Unmarshal(buffer, &capabilities)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal storage capability message: %w", err)
	}

	return &capabilities, nil
}

// HandleIncomingFileUploads handles incoming file uploads.
func (p *Protocol) HandleIncomingFileUploads(s network.Stream) {
	p.storage.HandleIncomingFileUploads(s)
}

// SetUploadingStatus sets an error or fhash if upload failed or completed.
func (p *Protocol) SetUploadingStatus(peerID peer.ID, filePath, fileHash string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fileWithPeer := filePath + peerID.String()
	st := p.uploadStatus[fileWithPeer]
	st.err = err
	st.fileHash = fileHash

	p.uploadStatus[fileWithPeer] = st
}

// ResetProgressAndCancelStatus resets the upload progress and if a previous cancellation was there, deletes it.
func (p *Protocol) ResetProgressAndCancelStatus(peerID peer.ID, filePath string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	fileWithPeer := filePath + peerID.String()
	delete(p.uploadStatus, fileWithPeer)
	delete(p.uploadProgress, fileWithPeer)
	delete(p.cancelUploads, fileWithPeer)
}

// SetCancelFileUpload sets a cancel file upload.
func (p *Protocol) SetCancelFileUpload(peerID peer.ID, filePath string, cancelled bool, cancel context.CancelFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()

	fileWithPeer := filePath + peerID.String()
	st := p.cancelUploads[fileWithPeer]

	st.cancelFunc = cancel
	st.cancelled = cancelled

	p.cancelUploads[fileWithPeer] = st
}

// GetCancelFileUploadStatus returns the status of a cancelled file upload.
func (p *Protocol) GetCancelFileUploadStatus(peerID peer.ID, filePath string) (bool, context.CancelFunc) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	fileWithPeer := filePath + peerID.String()
	st := p.cancelUploads[fileWithPeer]

	return st.cancelled, st.cancelFunc
}

// GetUploadProgress returns the number of bytes transferred to the remote node.
func (p *Protocol) GetUploadProgress(peerID peer.ID, filePath string) (int, string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	fileWithPeer := filePath + peerID.String()
	progress := p.uploadProgress[fileWithPeer]
	st, ok := p.uploadStatus[fileWithPeer]
	if !ok {
		st.fileHash = ""
		st.err = nil
	}
	return progress, st.fileHash, st.err
}

// UploadFileWithMetadata uploads a file content, its name and if its associated with a channel node item.
func (p *Protocol) UploadFileWithMetadata(ctx context.Context, peerID peer.ID, filePath string, publicKeyOwner []byte, feesPerByte string) (storage.FileMetadata, error) {
	request := &messages.StorageFileUploadMetadataProto{
		FileName:       filepath.Base(filePath),
		PublicKeyOwner: publicKeyOwner,
		FeesPerByte:    feesPerByte,
	}

	input, err := os.Open(filePath)
	if err != nil {
		return storage.FileMetadata{}, fmt.Errorf("failed to open the source file for uploading: %w", err)
	}
	defer input.Close()
	s, err := p.host.NewStream(ctx, peerID, FileUploadProtocolID)
	if err != nil {
		return storage.FileMetadata{}, fmt.Errorf("failed to create new file upload stream: %w", err)
	}
	defer s.Close()

	fileWithPeer := filePath + peerID.String()

	p.mu.Lock()
	_, ok := p.uploadProgress[fileWithPeer]
	if ok {
		p.mu.Unlock()
		return storage.FileMetadata{}, errors.New("file is already uploaded/uploading to remote node")
	}
	p.uploadProgress[fileWithPeer] = 0
	p.mu.Unlock()

	// reset the status by setting the error to nil
	p.SetUploadingStatus(peerID, filePath, "", nil)

	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return storage.FileMetadata{}, fmt.Errorf("failed to marshal a file upload request: %w", err)
	}

	requestBufferSize := 8 + len(requestBytes)
	if requestBufferSize > 20*common.KB {
		return storage.FileMetadata{}, fmt.Errorf("request size is too large for a sending a file to the remote node: %d", requestBufferSize)
	}

	requestPayloadWithLength := make([]byte, requestBufferSize)
	binary.LittleEndian.PutUint64(requestPayloadWithLength, uint64(len(requestBytes)))
	copy(requestPayloadWithLength[8:], requestBytes)
	_, err = s.Write(requestPayloadWithLength)
	if err != nil {
		return storage.FileMetadata{}, fmt.Errorf("failed to write file metadata to remote stream: %w", err)
	}

	buf := make([]byte, bufferSize)
	loopFinished := false
	for !loopFinished {
		select {
		case <-ctx.Done():
			p.SetUploadingStatus(peerID, filePath, "", errors.New("cancelled"))
			return storage.FileMetadata{}, fmt.Errorf("upload operation cancelled: %w", ctx.Err())
		default:
			n, err := input.Read(buf)
			if n > 0 {
				_, err := s.Write(buf[:n])
				if err != nil {
					return storage.FileMetadata{}, fmt.Errorf("failed to write content to remote stream: %w", err)
				}

				p.mu.Lock()
				uploaded := p.uploadProgress[fileWithPeer]
				uploaded += n
				p.uploadProgress[fileWithPeer] = uploaded
				p.mu.Unlock()
			}

			if err == io.EOF {
				loopFinished = true
			} else if err != nil {
				return storage.FileMetadata{}, fmt.Errorf("failed to write the file to remote stream: %w", err)
			}
		}
	}

	// we need to send EOF so we can move forward and read the response
	// below will trigger an eof and the remote peer will no longer read but can still write
	err = s.CloseWrite()
	if err != nil {
		return storage.FileMetadata{}, fmt.Errorf("failed to close local writer: %w", err)
	}

	metadataBytes, err := io.ReadAll(s)
	if err != nil {
		return storage.FileMetadata{}, fmt.Errorf("failed to get the uploaded file metadata from remote peer: %w", err)
	}

	metaData := storage.FileMetadata{}
	err = json.Unmarshal(metadataBytes, &metaData)
	if err != nil {
		return storage.FileMetadata{}, fmt.Errorf("failed to unmarshal file metadata response: %w", err)
	}

	p.SetUploadingStatus(peerID, filePath, metaData.Hash, nil)

	metaData.RemotePeer = peerID.String()

	return metaData, nil
}

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

		nn, err := s.Write(buf[:n])
		totalSent += nn
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
		return 0, fmt.Errorf("failed to connect to peer for speed test: %w", err)
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

	readBuf := make([]byte, bufferSize)
	start := time.Now()
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

// handleIncomingDiscoveredStorageTransfer is used to serve the current discovered storage providers from this peer.
// its used by clients behind NAT to discover storage providers.
func (p *Protocol) handleIncomingDiscoveredStorageTransfer(s network.Stream) {
	defer s.Close()
	providers := p.GetDiscoveredStorageProviders()
	data, err := json.Marshal(providers)
	if err != nil {
		log.Warnf("failed to marshal storage providers: %v", err)
		return
	}

	_, err = s.Write(data)
	if err != nil {
		log.Warnf("failed to write storage providers to stream: %v", err)
	}
}

// SendDiscoveredStorageTransferRequest sends a request to remote peer to get its discovered storage peers.
// it returns the number of peers transferred.
func (p *Protocol) SendDiscoveredStorageTransferRequest(ctx context.Context, peerID peer.ID) (int, error) {
	s, err := p.host.NewStream(ctx, peerID, DiscoveredPeersProtocolID)
	if err != nil {
		return 0, fmt.Errorf("failed to connect to peer for sending data query response: %w", err)
	}
	defer s.Close()

	maxBytes := int64(2 * common.MB)
	limitReader := io.LimitReader(s, maxBytes)
	buffer, err := io.ReadAll(limitReader)
	if err != nil {
		return 0, fmt.Errorf("failed to read storage providers data from stream: %w", err)
	}

	if len(buffer) == 0 {
		return 0, errors.New("failed to read data from stream")
	}

	providers := make([]ProviderWithCountry, 0)

	err = json.Unmarshal(buffer, &providers)
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal storage providers envelope: %w", err)
	}

	p.mu.Lock()
	for _, v := range providers {
		p.storageProviders[v.Response.StorageProviderPeerAddr] = v
	}
	p.mu.Unlock()

	return len(providers), nil
}

// handleIncomingStorageQueryResponse handles incoming storage query responses from storage provider nodes.
func (p *Protocol) handleIncomingStorageQueryResponse(s network.Stream) {
	buf, err := io.ReadAll(s)
	defer s.Close()
	if err != nil {
		log.Warnf("failed to read data from stream: %v", err)
		return
	}

	var country *geoip2.Country
	remoteIP, _ := getRemotePeerIP(s)
	netIP := net.ParseIP(remoteIP)
	if netIP != nil {
		country, err = p.ipLocator.Country(netIP)
		if err != nil {
			country = nil
		}
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
			[]byte(fmt.Sprintf("%d", tmp.StorageCapacity)),
			[]byte(fmt.Sprintf("%d", tmp.Uptime)),
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
		return
	}

	p.mu.Lock()
	p.storageProviders[tmp.StorageProviderPeerAddr] = ProviderWithCountry{
		Country:  country,
		Response: &tmp,
	}
	p.mu.Unlock()
}

// GetDiscoveredStorageProviders returns a list of discovered storage providers.
func (p *Protocol) GetDiscoveredStorageProviders() []ProviderWithCountry {
	p.mu.RLock()
	defer p.mu.RUnlock()

	providers := make([]ProviderWithCountry, 0)
	for _, v := range p.storageProviders {
		providers = append(providers, ProviderWithCountry{
			Country:  v.Country,
			Response: v.Response,
		})
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

func getRemotePeerIP(stream network.Stream) (string, error) {
	remoteMultiaddr := stream.Conn().RemoteMultiaddr()

	ip, err := remoteMultiaddr.ValueForProtocol(multiaddr.P_IP4)
	if err != nil {
		ip, err = remoteMultiaddr.ValueForProtocol(multiaddr.P_IP6)
		if err != nil {
			return "", err
		}
	}

	return ip, nil
}

type defaultIPLocator struct{}

// nolint:unparam
func (d *defaultIPLocator) Country(_ net.IP) (*geoip2.Country, error) {
	return nil, errors.New("failed to load the database")
}
