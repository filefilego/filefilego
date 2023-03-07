package blockdownloader

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// BlockDownloaderProtocolID represents the block downloader protocol version.
const BlockDownloaderProtocolID = "/ffg/block_downloader/1.0.0"

// BlockchainHeightProtocolID is the protocol which returns the blockchain height of a node.
const BlockchainHeightProtocolID = "/ffg/blockchain_height/1.0.0"

// Interface defines the block download protocol functionality.
type Interface interface {
	AddRemotePeer(remote *RemotePeer)
	RemoveRemotePeer(remote *RemotePeer)
	GetNextPeer() (*RemotePeer, error)
	Reset()
	GetRemotePeers() []*RemotePeer
	GetHeighestBlockNumberFromPeers() uint64
}

// Protocol implements the block downloader functionality.
type Protocol struct {
	blockchain    blockchain.Interface
	host          host.Host
	remotePeers   []*RemotePeer
	nextPeerIndex int
	mu            sync.RWMutex
}

// New creates a block downloader protocol.
func New(bchain blockchain.Interface, h host.Host) (*Protocol, error) {
	if bchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	if h == nil {
		return nil, errors.New("host is nil")
	}

	p := &Protocol{
		blockchain:  bchain,
		host:        h,
		remotePeers: make([]*RemotePeer, 0),
	}

	// listen for blockchain height request
	p.host.SetStreamHandler(BlockchainHeightProtocolID, p.onBlockchainHeightRequest)
	// listen for incoming block request
	p.host.SetStreamHandler(BlockDownloaderProtocolID, p.onBlockDownloadRequest)

	return p, nil
}

// GetRemotePeers gets a list of remote peers.
func (bd *Protocol) GetRemotePeers() []*RemotePeer {
	bd.mu.RLock()
	defer bd.mu.RUnlock()

	list := make([]*RemotePeer, len(bd.remotePeers))
	copy(list, bd.remotePeers)

	return list
}

// GetHeighestBlockNumberFromPeers gets the heighest block number from peers.
func (bd *Protocol) GetHeighestBlockNumberFromPeers() uint64 {
	height := uint64(0)
	peers := bd.GetRemotePeers()
	for _, v := range peers {
		if v.height > height {
			height = v.height
		}
	}
	return height
}

// AddRemotePeer adds a remote peer.
func (bd *Protocol) AddRemotePeer(remote *RemotePeer) {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	// prevents dupes
	for _, v := range bd.remotePeers {
		if v.peer.String() == remote.peer.String() {
			return
		}
	}

	bd.remotePeers = append(bd.remotePeers, remote)
}

// RemoveRemotePeer remove a peer.
func (bd *Protocol) RemoveRemotePeer(remote *RemotePeer) {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	if len(bd.remotePeers) == 0 {
		return
	}

	idx := -1
	for i, v := range bd.remotePeers {
		if v.peer.String() == remote.peer.String() {
			idx = i
			break
		}
	}

	if idx == -1 {
		return
	}

	bd.remotePeers = append(bd.remotePeers[:idx], bd.remotePeers[idx+1:]...)
}

// GetNextPeer returns next peer in a round robin way.
func (bd *Protocol) GetNextPeer() (*RemotePeer, error) {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	if len(bd.remotePeers) == 0 {
		return nil, errors.New("no peers in the list")
	}

	if bd.nextPeerIndex >= len(bd.remotePeers) {
		bd.nextPeerIndex = 0
	}

	remotePeer := bd.remotePeers[bd.nextPeerIndex]
	bd.nextPeerIndex++
	return remotePeer, nil
}

// Reset the internals.
func (bd *Protocol) Reset() {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	bd.remotePeers = []*RemotePeer{}
}

// onBlockDownloadRequest handles block downloads request.
func (bd *Protocol) onBlockDownloadRequest(s network.Stream) {
	c := bufio.NewReader(s)
	defer s.Close()

	// read the first 8 bytes to determine the size of the message
	msgLengthBuffer := make([]byte, 8)
	_, err := c.Read(msgLengthBuffer)
	if err != nil {
		log.Errorf("failed to read from block downloader stream: %s", err.Error())
		return
	}

	// create a buffer with the size of the message and then read until its full
	lengthPrefix := int64(binary.LittleEndian.Uint64(msgLengthBuffer))
	buf := make([]byte, lengthPrefix)

	// read the full message
	_, err = io.ReadFull(c, buf)
	if err != nil {
		log.Errorf("failed to read from stream to buffer: %s", err.Error())
		return
	}

	downloadRequest := messages.BlockDownloadRequestProto{}
	if err := proto.Unmarshal(buf, &downloadRequest); err != nil {
		log.Error("failed to unmarshall data from stream: " + err.Error())
		return
	}

	nodeHeight := bd.blockchain.GetHeight()
	downloadResponse := messages.BlockDownloadResponseProto{
		From:       downloadRequest.From,
		To:         downloadRequest.To,
		Error:      false,
		NodeHeight: nodeHeight,
		Blocks:     make([]*block.ProtoBlock, 0),
	}

	if (downloadRequest.From > downloadRequest.To) || (downloadRequest.To > nodeHeight) {
		downloadResponse.Error = true
	} else {
		for i := downloadRequest.From; i <= downloadRequest.To; i++ {
			blck, err := bd.blockchain.GetBlockByNumber(i)
			if err != nil {
				downloadResponse.Error = true
				downloadResponse.Blocks = []*block.ProtoBlock{}
				break
			} else {
				downloadResponse.Blocks = append(downloadResponse.Blocks, block.ToProtoBlock(*blck))
			}
		}
	}

	payload, err := proto.Marshal(&downloadResponse)
	if err != nil {
		log.Error("failed to marshal BlockQueryResponse")
		return
	}

	payloadBufferSize := 8 + len(payload)
	if payloadBufferSize > 64*common.MB {
		log.Errorf("response size is too large for a sending block ranges with size: %d", payloadBufferSize)
		return
	}

	payloadEnvelope := make([]byte, payloadBufferSize)
	binary.LittleEndian.PutUint64(payloadEnvelope, uint64(len(payload)))
	copy(payloadEnvelope[8:], payload)
	n, err := s.Write(payloadEnvelope)
	if err != nil {
		log.Errorf("failed to write envelope data to stream: %s", err.Error())
	}
	if n != len(payloadEnvelope) {
		log.Errorf("failed to write the envelope size %d to stream, wrote: %d ", len(payloadEnvelope), n)
	}
}

// onBlockchainHeightRequest handles the blockchain height request.
func (bd *Protocol) onBlockchainHeightRequest(s network.Stream) {
	response := messages.BlockchainHeightResponseProto{
		Height: bd.blockchain.GetHeight(),
	}
	data, _ := proto.Marshal(&response)
	n, err := s.Write(data)
	if err != nil || n != len(data) {
		log.Errorf("failed to write to block height stream: %s", err.Error())
	}
	s.Close()
}
