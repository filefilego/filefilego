package blockdownloader

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/filefilego/filefilego/internal/node/protocols/messages"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

const deadlineTimeInSecond = 10

// RemotePeer represents a peer with blockchain height.
type RemotePeer struct {
	host   host.Host
	peer   peer.ID
	height uint64
}

// NewRemotePeer creates a new remote peer.
func NewRemotePeer(h host.Host, peer peer.ID) (*RemotePeer, error) {
	if h == nil {
		return nil, errors.New("host is nil")
	}

	return &RemotePeer{
		host:   h,
		peer:   peer,
		height: 0,
	}, nil
}

// GetPeerID returns the peer id.
func (rp *RemotePeer) GetPeerID() peer.ID {
	return rp.peer
}

// CurrentHeight returns the current height of the peer.
func (rp *RemotePeer) CurrentHeight() uint64 {
	return rp.height
}

// DownloadBlocksRange downloads a range of blocks
func (rp *RemotePeer) DownloadBlocksRange(ctx context.Context, request *messages.BlockDownloadRequestProto) (*messages.BlockDownloadResponseProto, error) {
	s, err := rp.host.NewStream(ctx, rp.peer, BlockDownloaderProtocolID)
	if err != nil {
		return nil, fmt.Errorf("failed to create new download stream to remote peer: %w", err)
	}
	c := bufio.NewReader(s)
	defer s.Close()

	future := time.Now().Add(deadlineTimeInSecond * time.Second)
	err = s.SetDeadline(future)
	if err != nil {
		return nil, fmt.Errorf("failed to set block download stream deadline: %w", err)
	}

	requestBytes, err := proto.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal protobuf block request message: %w", err)
	}

	requestPayloadWithLength := make([]byte, 8+len(requestBytes))
	binary.LittleEndian.PutUint64(requestPayloadWithLength, uint64(len(requestBytes)))
	copy(requestPayloadWithLength[8:], requestBytes)
	_, err = s.Write(requestPayloadWithLength)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to download stream: %w", err)
	}

	responsePayloadLength := make([]byte, 8)
	_, err = c.Read(responsePayloadLength)
	if err != nil {
		return nil, fmt.Errorf("failed to read block response length: %w", err)
	}

	responseSize := int64(binary.LittleEndian.Uint64(responsePayloadLength))
	buf := make([]byte, responseSize)

	_, err = io.ReadFull(c, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read block response payload: %w", err)
	}

	response := messages.BlockDownloadResponseProto{}
	if err := proto.Unmarshal(buf, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal block download response: %w", err)
	}

	rp.height = response.NodeHeight

	return &response, nil
}

// GetHeight gets remote peers blockchain height.
func (rp *RemotePeer) GetHeight(ctx context.Context) (*messages.BlockchainHeightResponseProto, error) {
	s, err := rp.host.NewStream(ctx, rp.peer, BlockchainHeightProtocolID)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new block height stream to remote peer: %w", err)
	}
	defer s.Close()

	future := time.Now().Add(deadlineTimeInSecond * time.Second)
	err = s.SetDeadline(future)
	if err != nil {
		return nil, fmt.Errorf("failed to set get height stream deadline: %w", err)
	}

	// just send a single byte to trigger the stream handling logic on the other side
	_, err = s.Write([]byte("H"))
	if err != nil {
		return nil, fmt.Errorf("failed to write data into stream: %w", err)
	}

	buf, err := io.ReadAll(s)
	if err != nil {
		return nil, fmt.Errorf("failed to read all data from stream: %w", err)
	}

	response := messages.BlockchainHeightResponseProto{}
	if err := proto.Unmarshal(buf, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal data retrieved from the remote peer: %w", err)
	}
	rp.height = response.Height

	return &response, nil
}
