package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	ffgconfig "github.com/filefilego/filefilego/config"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
	blockdownloader "github.com/filefilego/filefilego/node/protocols/block_downloader"
	dataquery "github.com/filefilego/filefilego/node/protocols/data_query"
	"github.com/filefilego/filefilego/node/protocols/messages"
	storageprotocol "github.com/filefilego/filefilego/node/protocols/storage"
	"github.com/filefilego/filefilego/search"
	"github.com/filefilego/filefilego/storage"
	"github.com/filefilego/filefilego/transaction"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	libp2pdiscovery "github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/proto"
)

const findPeerTimeoutSeconds = 3

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

// Interface defines a node's functionalities.
type Interface interface {
	GetSyncing() bool
	Sync(ctx context.Context) error
	ConnectToPeerWithMultiaddr(ctx context.Context, addr multiaddr.Multiaddr) (*peer.AddrInfo, error)
	Advertise(ctx context.Context, ns string)
	DiscoverPeers(ctx context.Context, ns string) error
	PublishMessageToNetwork(ctx context.Context, topicName string, data []byte) error
	HandleIncomingMessages(ctx context.Context, topicName string) error
	GetMultiaddr() ([]multiaddr.Multiaddr, error)
	Peers() peer.IDSlice
	GetID() string
	GetPeerID() peer.ID
	Bootstrap(ctx context.Context, bootstrapPeers []string) error
	FindPeers(ctx context.Context, peerIDs []peer.ID) []peer.AddrInfo
	JoinPubSubNetwork(ctx context.Context, topicName string) error
	HeighestBlockNumberDiscovered() uint64
}

// Node represents all the node functionalities
type Node struct {
	host                    host.Host
	dht                     PeerFinderBootstrapper
	discovery               libp2pdiscovery.Discovery
	pubSub                  PublishSubscriber
	searchEngine            search.IndexSearcher
	storage                 storage.Interface
	blockchain              blockchain.Interface
	dataQueryProtocol       dataquery.Interface
	blockDownloaderProtocol blockdownloader.Interface
	storageProtocol         storageprotocol.Interface

	syncing   bool
	syncingMu sync.RWMutex

	heighestBlockNumberDiscovered uint64
	heighestBlockNumberMu         sync.RWMutex

	config      *ffgconfig.Config
	gossipTopic map[string]*pubsub.Topic

	uptime int64
}

// New creates a new node.
func New(cfg *ffgconfig.Config, host host.Host, dht PeerFinderBootstrapper, discovery libp2pdiscovery.Discovery, pubSub PublishSubscriber, search search.IndexSearcher, storage storage.Interface, blockchain blockchain.Interface, dataQuery dataquery.Interface, blockDownloaderProtocol blockdownloader.Interface, storageProtocol storageprotocol.Interface) (*Node, error) {
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

	if storage == nil {
		return nil, errors.New("storage is nil")
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

	if storageProtocol == nil {
		return nil, errors.New("storageProtocol is nil")
	}

	return &Node{
		host:                    host,
		dht:                     dht,
		discovery:               discovery,
		pubSub:                  pubSub,
		searchEngine:            search,
		storage:                 storage,
		blockchain:              blockchain,
		dataQueryProtocol:       dataQuery,
		blockDownloaderProtocol: blockDownloaderProtocol,
		storageProtocol:         storageProtocol,
		config:                  cfg,
		gossipTopic:             make(map[string]*pubsub.Topic),
		uptime:                  time.Now().Unix(),
	}, nil
}

// nolint:misspell
// HeighestBlockNumberDiscovered gets the heighest block discovered from other peers in the network.
func (n *Node) HeighestBlockNumberDiscovered() uint64 {
	n.heighestBlockNumberMu.RLock()
	defer n.heighestBlockNumberMu.RUnlock()

	return n.heighestBlockNumberDiscovered
}

func (n *Node) setHeighestBlockNumberDiscovered(height uint64) {
	n.heighestBlockNumberMu.Lock()
	defer n.heighestBlockNumberMu.Unlock()

	n.heighestBlockNumberDiscovered = height
}

func (n *Node) setSyncing(val bool) {
	n.syncingMu.Lock()
	defer n.syncingMu.Unlock()
	n.syncing = val
}

// GetSyncing returns true if node is syncing.
func (n *Node) GetSyncing() bool {
	n.syncingMu.Lock()
	defer n.syncingMu.Unlock()
	return n.syncing
}

// Sync the node with other peers in the network.
func (n *Node) Sync(ctx context.Context) error {
	if n.GetSyncing() {
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
			defer wg.Done()
			remotePeer, err := blockdownloader.NewRemotePeer(n.host, p)
			if err != nil {
				log.Warnf("failed to create remote peer: %v", err)
				return
			}

			_, err = remotePeer.GetHeight(ctx)
			if err != nil {
				log.Warnf("failed to get height of remote peer: %v", err)
				return
			}

			n.blockDownloaderProtocol.AddRemotePeer(remotePeer)
		}(p, &wg)
	}
	wg.Wait()
	// we have a list of valid remote peers
	remotePeersList := n.blockDownloaderProtocol.GetRemotePeers()
	log.Infof("syncing with nodes: %d", len(remotePeersList))
	if len(remotePeersList) > 0 {
		// while this node is behind the network
		// try to download blocks
		heighestBlockNumberDiscovered := n.blockDownloaderProtocol.GetHeighestBlockNumberFromPeers()
		n.setHeighestBlockNumberDiscovered(heighestBlockNumberDiscovered)

		for n.blockchain.GetHeight() <= heighestBlockNumberDiscovered {
			localHeight := n.blockchain.GetHeight()
			request := messages.BlockDownloadRequestProto{
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
				continue
			}

			if blockResponse == nil {
				continue
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
			log.Info("connected to: ", peer.ID.Pretty())
		}
	}
	return nil
}

// PublishMessageToNetwork publish a message to the network.
func (n *Node) PublishMessageToNetwork(ctx context.Context, topicName string, data []byte) error {
	topic, ok := n.gossipTopic[topicName]
	if !ok {
		return errors.New("pubsub topic is not available")
	}

	if err := topic.Publish(ctx, data); err != nil {
		return fmt.Errorf("failed to publish message to network: %w", err)
	}
	return nil
}

// JoinPubSubNetwork joins the gossip network.
func (n *Node) JoinPubSubNetwork(ctx context.Context, topicName string) error {
	_, ok := n.gossipTopic[topicName]
	if ok {
		return errors.New("already subscribed to topic")
	}

	topic, err := n.pubSub.Join(topicName)
	if err != nil {
		return fmt.Errorf("failed to join pubsub topic: %w", err)
	}

	n.gossipTopic[topicName] = topic
	return nil
}

// HandleIncomingMessages gets the messages from gossip network.
func (n *Node) HandleIncomingMessages(ctx context.Context, topicName string) error {
	topic, ok := n.gossipTopic[topicName]
	if !ok {
		return errors.New("not subscribed to a topic")
	}

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

			err = n.processIncomingMessage(ctx, msg)
			if err != nil {
				log.Errorf("failed to process incoming message: %v", err)
			}
		}
	}()
	return nil
}

func (n *Node) processIncomingMessage(ctx context.Context, message *pubsub.Message) error {
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

	case *messages.GossipPayload_StorageQuery:
		if !n.config.Global.StoragePublic {
			return nil
		}

		if n.host.ID().String() == message.ReceivedFrom.String() {
			return nil
		}

		pubKey, err := n.host.ID().ExtractPublicKey()
		if err != nil {
			return fmt.Errorf("failed to extract public key from host: %w", err)
		}

		pubKeyBytes, err := pubKey.Raw()
		if err != nil {
			return fmt.Errorf("failed to get public key bytes: %w", err)
		}

		storageDirCapacity := uint64(0)
		if n.config.Global.ShowStorageCapacity {
			storageDirCapacity, err = common.GetDirectoryFreeSpace(n.config.Global.StorageDir)
			if err != nil {
				log.Warnf("failed to get storage folder capacity: %v", err)
			}
		}

		response := messages.StorageQueryResponseProto{
			StorageProviderPeerAddr: n.GetID(),
			Location:                n.config.Global.StorageNodeLocation,
			FeesPerByte:             n.config.Global.StorageFeesPerByte,
			PublicKey:               make([]byte, len(pubKeyBytes)),
			StorageCapacity:         storageDirCapacity,
			Uptime:                  time.Now().Unix() - n.uptime,
		}

		copy(response.PublicKey, pubKeyBytes)
		data := bytes.Join(
			[][]byte{
				[]byte(response.StorageProviderPeerAddr),
				[]byte(response.Location),
				[]byte(response.FeesPerByte),
				response.PublicKey,
				[]byte(fmt.Sprintf("%d", response.StorageCapacity)),
				[]byte(fmt.Sprintf("%d", response.Uptime)),
			},
			[]byte{},
		)

		h := sha256.New()
		if _, err := h.Write(data); err != nil {
			return fmt.Errorf("failed to hash the storage query response: %w", err)
		}
		hash := h.Sum(nil)
		privateKey := n.host.Peerstore().PrivKey(n.GetPeerID())
		sig, err := privateKey.Sign(hash)
		if err != nil {
			return fmt.Errorf("failed to sign storage query response: %w", err)
		}

		response.Hash = make([]byte, len(hash))
		response.Signature = make([]byte, len(sig))

		copy(response.Hash, hash)
		copy(response.Signature, sig)

		storageQueryProto := payload.GetStorageQuery()
		storageQuerier, err := peer.Decode(storageQueryProto.FromPeerAddr)
		if err != nil {
			return fmt.Errorf("failed to decode storage querier peer id: %w", err)
		}

		_ = n.FindPeers(ctx, []peer.ID{storageQuerier})
		err = n.storageProtocol.SendStorageQueryResponse(ctx, storageQuerier, &response)
		if err != nil {
			log.Warnf("failed to send data query response back to initiator: %v", err)
		}

	case *messages.GossipPayload_Query:
		// handle incoming data query
		if !n.config.Global.Storage {
			return nil
		}

		pubKey, err := n.host.ID().ExtractPublicKey()
		if err != nil {
			return fmt.Errorf("failed to extract public key from host: %w", err)
		}

		pubKeyBytes, err := pubKey.Raw()
		if err != nil {
			return fmt.Errorf("failed to get public key bytes: %w", err)
		}

		dataQueryRequestProto := payload.GetQuery()
		dataQueryRequest := messages.ToDataQueryRequest(dataQueryRequestProto)
		if err := dataQueryRequest.Validate(); err != nil {
			return fmt.Errorf("failed to validate data query request: %w", err)
		}

		response := messages.DataQueryResponse{
			FromPeerAddr:          n.GetID(),
			UnavailableFileHashes: make([][]byte, 0),
			FileHashes:            make([][]byte, 0),
			FileHashesSizes:       make([]uint64, 0),
			HashDataQueryRequest:  make([]byte, len(dataQueryRequest.Hash)),
			PublicKey:             make([]byte, len(pubKeyBytes)),
			Timestamp:             time.Now().Unix(),
			FileMerkleRootHashes:  make([][]byte, 0),
			FileNames:             make([]string, 0),
		}

		for _, v := range dataQueryRequest.FileHashes {
			fileMetaData, err := n.storage.GetFileMetadata(hexutil.EncodeNoPrefix(v), n.GetID())
			if err != nil {
				response.UnavailableFileHashes = append(response.UnavailableFileHashes, v)
				continue
			}
			response.FileHashes = append(response.FileHashes, v)
			response.FileHashesSizes = append(response.FileHashesSizes, uint64(fileMetaData.Size))
			merkleRootHash, err := hexutil.Decode(fileMetaData.MerkleRootHash)
			if err == nil {
				response.FileMerkleRootHashes = append(response.FileMerkleRootHashes, merkleRootHash)
				response.FileNames = append(response.FileNames, fileMetaData.FileName)
			}
		}

		if len(response.FileHashes) == 0 {
			return nil
		}

		storageFeesPerByte, ok := big.NewInt(0).SetString(n.config.Global.StorageFeesPerByte, 10)
		if !ok {
			return errors.New("failed to parse storage fees per gb from config")
		}

		if err != nil {
			return fmt.Errorf("failed to calculate files fees: %w", err)
		}
		response.FeesPerByte = hexutil.EncodeBig(storageFeesPerByte)
		copy(response.HashDataQueryRequest, dataQueryRequest.Hash)
		copy(response.PublicKey, pubKeyBytes)
		signature, err := messages.SignDataQueryResponse(n.host.Peerstore().PrivKey(n.GetPeerID()), response)
		if err != nil {
			return fmt.Errorf("failed to sign data query response: %w", err)
		}
		response.Signature = make([]byte, len(signature))
		copy(response.Signature, signature)

		fileRequesterID, err := peer.Decode(dataQueryRequest.FromPeerAddr)
		if err != nil {
			return fmt.Errorf("failed get the file requester peerd id: %w", err)
		}

		// send to requester, if it fails
		// then send to verifiers
		verfiers := block.GetBlockVerifiers()
		peerIDs := make([]peer.ID, 0)
		peerIDs = append(peerIDs, fileRequesterID)

		for _, v := range verfiers {
			publicKey, err := ffgcrypto.PublicKeyFromHex(v.PublicKey)
			if err != nil {
				continue
			}

			peerID, err := peer.IDFromPublicKey(publicKey)
			if err != nil {
				continue
			}
			peerIDs = append(peerIDs, peerID)
		}

		_ = n.FindPeers(ctx, peerIDs)
		err = n.dataQueryProtocol.SendDataQueryResponse(ctx, fileRequesterID, messages.ToDataQueryResponseProto(response))
		if err != nil {
			var wg sync.WaitGroup
			for _, peerID := range peerIDs {
				// skip the file requester
				if peerID.String() == fileRequesterID.String() {
					continue
				}
				wg.Add(1)
				go func(peerID peer.ID) {
					defer wg.Done()
					err := n.dataQueryProtocol.SendDataQueryResponse(ctx, peerID, messages.ToDataQueryResponseProto(response))
					if err != nil {
						log.Warnf("failed to sent data query response to verifiers: %v", err)
					}
				}(peerID)
			}
			wg.Wait()
		}
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
			} else {
				log.Warnf("failed to find peer: %v", err)
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

func calculateFileFees(storageFeesByte string, totalSize int64) (*big.Int, error) {
	storageFeesPerByte, ok := big.NewInt(0).SetString(storageFeesByte, 10)
	if !ok {
		return nil, fmt.Errorf("storage fees per GB is an incorrect format: %s", storageFeesByte)
	}

	return storageFeesPerByte.Mul(storageFeesPerByte, big.NewInt(totalSize)), nil
}
