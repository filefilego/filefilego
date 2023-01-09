package node

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/blockchain"
	"github.com/filefilego/filefilego/internal/search"
	"github.com/filefilego/filefilego/internal/transaction"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	libp2pdiscovery "github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

const findPeerTimeoutSeconds = 5

type PublishSubscriber interface {
	// Publish to a topic.
	Publish(topic string, data []byte, opts ...pubsub.PubOpt) error
	// Join a topic.
	Join(topic string, opts ...pubsub.TopicOpt) (*pubsub.Topic, error)
	// Subscribe to a topic.
	Subscribe(topic string, opts ...pubsub.SubOpt) (*pubsub.Subscription, error)
}

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
	pubSub       PublishSubscriber
	searchEngine search.IndexSearcher
	blockchain   blockchain.InterfaceBlockchain
	gossipTopic  *pubsub.Topic
}

// New creates a new node.
func New(host host.Host, dht PeerFinderBootstrapper, discovery libp2pdiscovery.Discovery, pubSub PublishSubscriber, search search.IndexSearcher, blockchain blockchain.InterfaceBlockchain) (*Node, error) {
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

	if pubSub == nil {
		return nil, errors.New("pubSub is nil")
	}

	if blockchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	return &Node{
		host:         host,
		dht:          dht,
		discovery:    discovery,
		pubSub:       pubSub,
		searchEngine: search,
		blockchain:   blockchain,
	}, nil
}

// GetMultiAddrFromString gets the multiaddress from the string encoded address.
func GetMultiAddrFromString(addr string) (multiaddr.Multiaddr, error) {
	maddr, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to validate multiaddr: %w", err)
	}
	return maddr, nil
}

// ConnectToPeerWithMultiaddr connects to a node given its full address.
func (n *Node) ConnectToPeerWithMultiaddr(ctx context.Context, addr multiaddr.Multiaddr) (*peer.AddrInfo, error) {
	p, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to get info from p2p addr: %w", err)
	}
	if err := n.host.Connect(ctx, *p); err != nil {
		return nil, fmt.Errorf("failed to connect to host: %w", err)
	}

	return p, nil
}

// Advertise randevouz point.
func (n *Node) Advertise(ctx context.Context, ns string) {
	dutil.Advertise(ctx, n.discovery, ns)
}

// DiscoverPeers discovers peers from randevouz point.
func (n *Node) DiscoverPeers(ctx context.Context, ns string) error {
	peerChan, err := n.discovery.FindPeers(ctx, ns)
	if err != nil {
		return fmt.Errorf("failed to find peers: %w", err)
	}
	for peer := range peerChan {
		if peer.ID == n.host.ID() {
			continue
		}
		err := n.host.Connect(ctx, peer)
		if err != nil {
			log.Println("Failed connecting to ", peer.ID.Pretty(), ", error:", err)
		} else {
			log.Println("Connected to:", peer.ID.Pretty())
		}
	}
	return nil
}

// PublishMessageToNetwork publish a message to the network.
func (n *Node) PublishMessageToNetwork(ctx context.Context, data []byte) error {
	if n.gossipTopic == nil {
		return errors.New("pubsub topic is not available")
	}

	err := n.gossipTopic.Publish(ctx, data)
	if err != nil {
		return fmt.Errorf("failed to publish message to network: %w", err)
	}
	return nil
}

// HandleIncomingMessages gets the messages from gossip network.
func (n *Node) HandleIncomingMessages(ctx context.Context, topicName string) error {
	if n.gossipTopic != nil {
		return errors.New("already subscribed to topic")
	}

	topic, err := n.pubSub.Join(topicName)
	if err != nil {
		return fmt.Errorf("failed to join pubsub topic: %w", err)
	}

	n.gossipTopic = topic

	sub, err := topic.Subscribe()
	if err != nil {
		return fmt.Errorf("failed to subscribe to topic %s: %w", topicName, err)
	}

	go func() {
		for {
			msg, err := sub.Next(ctx)
			if err != nil {
				log.Println("error ", err)
				continue
			}

			err = n.processIncomingMessage(msg)
			if err != nil {
				log.Println("error ", err)
			}
		}
	}()
	return nil
}

func (n *Node) processIncomingMessage(message *pubsub.Message) error {
	payload := GossipPayload{}
	if err := proto.Unmarshal(message.Data, &payload); err != nil {
		return fmt.Errorf("failed to unmarshal pubsub data: %w", err)
	}
	msg := payload.GetMessage()
	switch msg.(type) {
	case *GossipPayload_Blocks:
		// handle incoming blocks
		if n.host.ID().String() == message.ReceivedFrom.String() {
			return nil
		}

		protoBlocks := payload.GetBlocks().GetBlocks()
		for _, b := range protoBlocks {
			retrivedBlock := block.ProtoBlockToBlock(b)
			ok, err := retrivedBlock.Validate()
			if err != nil {
				return fmt.Errorf("failed to validate incoming block: %w", err)
			}
			if ok {
				err := n.blockchain.PutBlockPool(retrivedBlock)
				if err != nil {
					return fmt.Errorf("failed to insert block to blockPool: %w", err)
				}
			}
		}

	case *GossipPayload_Transaction:
		// handle incoming transaction
		if n.host.ID().String() == message.ReceivedFrom.String() {
			return nil
		}
		tx := transaction.ProtoTransactionToTransaction(payload.GetTransaction())
		ok, err := tx.Validate()
		if err != nil {
			return fmt.Errorf("failed to validate incoming transaction: %w", err)
		}
		if ok {
			err := n.blockchain.PutMemPool(tx)
			if err != nil {
				return fmt.Errorf("failed to insert transaction to mempool: %w", err)
			}
		}

	case *GossipPayload_Query:
		// handle incoming data query
	}
	return nil
}

// GetMultiaddr returns the peers multiaddr.
func (n *Node) GetMultiaddr() ([]multiaddr.Multiaddr, error) {
	peerInfo := peer.AddrInfo{
		ID:    n.host.ID(),
		Addrs: n.host.Addrs(),
	}
	return peer.AddrInfoToP2pAddrs(&peerInfo)
}

// Peers returns a list of peers in the peer store.
func (n *Node) Peers() peer.IDSlice {
	return n.host.Peerstore().Peers()
}

// GetID returns the node id.
func (n *Node) GetID() string {
	return n.host.ID().String()
}

// GetPeerID returns the peer id struct.
func (n *Node) GetPeerID() peer.ID {
	return n.host.ID()
}

// Bootstrap connects to bootstrap nodes.
func (n *Node) Bootstrap(ctx context.Context, bootstrapPeers []string) error {
	if err := n.dht.Bootstrap(ctx); err != nil {
		return fmt.Errorf("failed to prepare this node for bootstraping: %w", err)
	}

	if len(bootstrapPeers) > 0 {
		var wg sync.WaitGroup
		for _, peerAddr := range bootstrapPeers {
			if peerAddr == "" {
				continue
			}

			wg.Add(1)
			go func(peer string) {
				defer wg.Done()
				maddr, err := GetMultiAddrFromString(peer)
				if err != nil {
					log.Println("failed to get multiaddr: ", err)
				}
				_, err = n.ConnectToPeerWithMultiaddr(ctx, maddr)
				if err != nil {
					log.Println("failed to connect to peer: ", err)
				}
			}(peerAddr)
		}
		wg.Wait()
	}

	return nil
}

// FindPeers returns the list of peer addresses.
func (n *Node) FindPeers(ctx context.Context, peerIDs []peer.ID) []peer.AddrInfo {
	discoveredPeers := []peer.AddrInfo{}
	var wg sync.WaitGroup
	mutex := sync.Mutex{}
	for _, peerAddr := range peerIDs {
		wg.Add(1)
		go func(peer peer.ID) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, findPeerTimeoutSeconds*time.Second)
			defer cancel()
			addr, err := n.dht.FindPeer(ctx, peer)
			if err == nil {
				mutex.Lock()
				discoveredPeers = append(discoveredPeers, addr)
				mutex.Unlock()
			}
		}(peerAddr)
	}
	wg.Wait()
	return discoveredPeers
}
