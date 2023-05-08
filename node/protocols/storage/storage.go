package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"
)

// ProtocolID represents the response protocol version
const ProtocolID = "/ffg/storagequery_response/1.0.0"

// Interface represents a set of functionalities by the storage query.
type Interface interface {
	SendStorageQueryResponse(ctx context.Context, peerID peer.ID, payload *messages.StorageQueryResponseProto) error
}

// Protocol wraps the storage protocols and handlers.
type Protocol struct {
	host host.Host
}

// New creates a storage protocol.
func New(h host.Host) (*Protocol, error) {
	if h == nil {
		return nil, errors.New("host is nil")
	}
	p := &Protocol{
		host: h,
	}

	// p.host.SetStreamHandler(ProtocolID, p.handleIncomingDataQueryResponse)
	// p.host.SetStreamHandler(DataQueryResponseTransferProtocolID, p.handleDataQueryResponseTransfer)

	return p, nil
}

// SendStorageQueryResponse sends back the storage query response to initiator.
func (d *Protocol) SendStorageQueryResponse(ctx context.Context, peerID peer.ID, payload *messages.StorageQueryResponseProto) error {
	s, err := d.host.NewStream(ctx, peerID, ProtocolID)
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
