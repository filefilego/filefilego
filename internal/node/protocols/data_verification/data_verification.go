package dataverification

import (
	"errors"

	"github.com/filefilego/filefilego/internal/contract"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
)

// ReceiveMerkleTreeProtocolID is a protocol which receives the merkle tree nodes.
const ReceiveMerkleTreeProtocolID = "/ffg/dataverification_receive_merkletree/1.0.0"

// Protocol wraps the data verification protocols and handlers
type Protocol struct {
	host          host.Host
	contractStore contract.Interface
}

// New creates a data verification protocol.
func New(h host.Host, contractStore contract.Interface) (*Protocol, error) {
	if h == nil {
		return nil, errors.New("host is nil")
	}

	if contractStore == nil {
		return nil, errors.New("contract store is nil")
	}

	p := &Protocol{
		host:          h,
		contractStore: contractStore,
	}

	p.host.SetStreamHandler(ReceiveMerkleTreeProtocolID, p.HandleIncomingMerkleTreeNodes)
	return p, nil
}

// HandleIncomingMerkleTreeNodes handles incoming merkle tree nodes from a node.
// this protocol handler is used by a verifier.
func (d *Protocol) HandleIncomingMerkleTreeNodes(s network.Stream) {
	// contract hash
	// file hash
}
