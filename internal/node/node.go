package node

import (
	"context"
	"errors"

	"github.com/filefilego/filefilego/internal/search"
	libp2pdiscovery "github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

// PeerFinderBootstrapper is a dht interface.
type PeerFinderBootstrapper interface {
	FindPeer(ctx context.Context, id peer.ID) (_ peer.AddrInfo, err error)
	Bootstrap(ctx context.Context) error
}

// Node represents all the node functionalities
type Node struct {
	host         host.Host
	dht          PeerFinderBootstrapper
	discovery    libp2pdiscovery.Discovery
	searchEngine search.IndexSearcher
}

// NewNode creates a new node.
func NewNode(host host.Host, dht PeerFinderBootstrapper, discovery libp2pdiscovery.Discovery, search search.IndexSearcher) (*Node, error) {
	if host == nil {
		return nil, errors.New("host is nil")
	}

	if dht == nil {
		return nil, errors.New("dht is nil")
	}

	if discovery == nil {
		return nil, errors.New("discovery is nil")
	}

	if search == nil {
		return nil, errors.New("search is nil")
	}

	return &Node{
		host:         host,
		dht:          dht,
		discovery:    discovery,
		searchEngine: search,
	}, nil
}

func (n *Node) Peers() peer.IDSlice {
	return n.host.Peerstore().Peers()
}
