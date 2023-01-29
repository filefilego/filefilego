package node

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	ffgconfig "github.com/filefilego/filefilego/config"
	"github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/blockchain"
	blockdownloader "github.com/filefilego/filefilego/internal/node/protocols/block_downloader"
	dataquery "github.com/filefilego/filefilego/internal/node/protocols/data_query"
	"github.com/filefilego/filefilego/internal/node/protocols/messages"
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

// PublishSubscriber is a pub sub interface.
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
	host                    host.Host
	dht                     PeerFinderBootstrapper
	discovery               libp2pdiscovery.Discovery
	pubSub                  PublishSubscriber
	searchEngine            search.IndexSearcher
	blockchain              blockchain.Interface
	dataQueryProtocol       dataquery.Interface
	blockDownloaderProtocol blockdownloader.Interface

	syncing     bool
	syncingMu   sync.RWMutex
	config      *ffgconfig.Config
	gossipTopic *pubsub.Topic
}

// New creates a new node.
func New(cfg *ffgconfig.Config, host host.Host, dht PeerFinderBootstrapper, discovery libp2pdiscovery.Discovery, pubSub PublishSubscriber, search search.IndexSearcher, blockchain blockchain.Interface, dataQuery dataquery.Interface, blockDownloaderProtocol blockdownloader.Interface) (*Node, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}

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

	if dataQuery == nil {
		return nil, errors.New("dataQuery is nil")
	}

	if blockDownloaderProtocol == nil {
		return nil, errors.New("blockDownloader is nil")
	}

	return &Node{
		host:                    host,
		dht:                     dht,
		discovery:               discovery,
		pubSub:                  pubSub,
		searchEngine:            search,
		blockchain:              blockchain,
		dataQueryProtocol:       dataQuery,
		blockDownloaderProtocol: blockDownloaderProtocol,
		config:                  cfg,
	}, nil
}

func (n *Node) setSyncing(val bool) {
	n.syncingMu.Lock()
	defer n.syncingMu.Unlock()
	n.syncing = val
}

func (n *Node) getSyncing() bool {
	n.syncingMu.Lock()
	defer n.syncingMu.Unlock()
	return n.syncing
}

// Sync the node with other peers in the network.
func (n *Node) Sync(ctx context.Context) error {
	if n.getSyncing() {
		return nil
	}

	n.setSyncing(true)
	defer n.setSyncing(false)

	n.blockDownloaderProtocol.Reset()
	var wg sync.WaitGroup
	for _, p := range n.Peers() {
		if p.String() == n.host.ID().String() {
			continue
		}

		wg.Add(1)
		go func(p peer.ID, wg *sync.WaitGroup) {
			remotePeer, err := blockdownloader.NewRemotePeer(n.host, p)
			if err != nil {
				log.Warnf("failed to create remote peer: %s", err.Error())
				wg.Done()
				return
			}

			_, err = remotePeer.GetHeight(ctx)
			if err != nil {
				log.Warnf("failed to get height of remote peer: %s", err.Error())
				wg.Done()
				return
			}

			n.blockDownloaderProtocol.AddRemotePeer(remotePeer)
			wg.Done()
		}(p, &wg)
	}
	wg.Wait()
	// we have a list of valid remote peers
	remotePeersList := n.blockDownloaderProtocol.GetRemotePeers()
	log.Infof("syncing with nodes: %d", len(remotePeersList))
	if len(remotePeersList) > 0 {
		// while this node is behind the network
		// try to download blocks
		for n.blockchain.GetHeight() <= n.blockDownloaderProtocol.GetHeighestBlockNumberFromPeers() {
			localHeight := n.blockchain.GetHeight()
			request := messages.BlockDownloadRequest{
				From: localHeight + 1,
				To:   localHeight + 100,
			}

			remotePeer, err := n.blockDownloaderProtocol.GetNextPeer()
			if err != nil {
				log.Warn("no remote peers to download blocks from")
				break
			}

			if n.blockchain.GetHeight() > remotePeer.CurrentHeight() {
				n.blockDownloaderProtocol.RemoveRemotePeer(remotePeer)
				continue
			}

			if request.To > remotePeer.CurrentHeight() {
				request.To = remotePeer.CurrentHeight()
			}

			blockResponse, err := remotePeer.DownloadBlocksRange(ctx, &request)
			if err != nil || blockResponse.Error {
				n.blockDownloaderProtocol.RemoveRemotePeer(remotePeer)
			}

			if len(blockResponse.Blocks) > 0 {
				log.Infof("downloaded %d blocks from peer %s", len(blockResponse.Blocks), remotePeer.GetPeerID().String())
			}

			for _, blck := range blockResponse.Blocks {
				if err := n.blockchain.PutBlockPool(block.ProtoBlockToBlock(blck)); err != nil {
					return fmt.Errorf("failed to insert the downloaded block to blockPool: %w", err)
				}
			}

			if blockResponse.NodeHeight <= n.blockchain.GetHeight() {
				n.blockDownloaderProtocol.RemoveRemotePeer(remotePeer)
			}
		}
	}

	return nil
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
		if err := n.host.Connect(ctx, peer); err != nil {
			log.Warnf("failed connecting to %s with error: %v", peer.ID.Pretty(), err)
		} else {
			log.Info("Connected to: ", peer.ID.Pretty())
		}
	}
	return nil
}

// PublishMessageToNetwork publish a message to the network.
func (n *Node) PublishMessageToNetwork(ctx context.Context, data []byte) error {
	if n.gossipTopic == nil {
		return errors.New("pubsub topic is not available")
	}

	if err := n.gossipTopic.Publish(ctx, data); err != nil {
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
				log.Errorf("failed to read next message from subscription: %v", err)
				continue
			}

			err = n.processIncomingMessage(msg)
			if err != nil {
				log.Errorf("failed to process incoming message: %v", err)
			}
		}
	}()
	return nil
}

func (n *Node) processIncomingMessage(message *pubsub.Message) error {
	payload := messages.GossipPayload{}
	if err := proto.Unmarshal(message.Data, &payload); err != nil {
		return fmt.Errorf("failed to unmarshal pubsub data: %w", err)
	}
	msg := payload.GetMessage()
	switch msg.(type) {
	case *messages.GossipPayload_Blocks:
		// handle incoming blocks
		if n.host.ID().String() == message.ReceivedFrom.String() {
			return nil
		}

		protoBlocks := payload.GetBlocks().GetBlocks()
		for _, b := range protoBlocks {
			retrivedBlock := block.ProtoBlockToBlock(b)
			log.Infof("block %d received from peer %s | local blockchain height: %d", retrivedBlock.Number, message.ReceivedFrom.String(), n.blockchain.GetHeight())
			ok, err := retrivedBlock.Validate()
			if err != nil {
				return fmt.Errorf("failed to validate incoming block: %w", err)
			}
			if ok {
				if err := n.blockchain.PutBlockPool(retrivedBlock); err != nil {
					return fmt.Errorf("failed to insert block to blockPool: %w", err)
				}
			}
		}

	case *messages.GossipPayload_Transaction:
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
			if err := n.blockchain.PutMemPool(tx); err != nil {
				return fmt.Errorf("failed to insert transaction to mempool: %w", err)
			}
		}

	case *messages.GossipPayload_Query:
		// handle incoming data query
		if !n.config.Global.Storage {
			return nil
		}
		dataQueryRequest := payload.GetQuery()
		fromPeer, err := peer.Decode(dataQueryRequest.FromPeerAddr)
		if err != nil {
			return fmt.Errorf("failed to decode the peer from the proto request: %w", err)
		}
		log.Info("from peer: ", fromPeer)
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
					log.Warnf("failed to get multiaddr: %v", err)
				}
				_, err = n.ConnectToPeerWithMultiaddr(ctx, maddr)
				if err != nil {
					log.Warnf("failed to connect to peer: %v", err)
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

// GetMultiAddrFromString gets the multiaddress from the string encoded address.
func GetMultiAddrFromString(addr string) (multiaddr.Multiaddr, error) {
	maddr, err := multiaddr.NewMultiaddr(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to validate multiaddr: %w", err)
	}
	return maddr, nil
}
