package node

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	ffgconfig "github.com/filefilego/filefilego/config"
	block "github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/blockchain"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	ffgcrypto "github.com/filefilego/filefilego/internal/crypto"
	"github.com/filefilego/filefilego/internal/database"
	blockdownloader "github.com/filefilego/filefilego/internal/node/protocols/block_downloader"
	dataquery "github.com/filefilego/filefilego/internal/node/protocols/data_query"
	"github.com/filefilego/filefilego/internal/node/protocols/messages"
	"github.com/filefilego/filefilego/internal/search"
	transaction "github.com/filefilego/filefilego/internal/transaction"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	libp2pdiscovery "github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
	"google.golang.org/protobuf/proto"
)

func TestNew(t *testing.T) {
	t.Parallel()

	h := newHost(t, "1032")
	kademliaDHT, err := dht.New(context.Background(), h, dht.Mode(dht.ModeServer))
	assert.NoError(t, err)

	dataQueryProtocol, err := dataquery.New(h)
	assert.NoError(t, err)

	cases := map[string]struct {
		host                    host.Host
		dht                     PeerFinderBootstrapper
		discovery               libp2pdiscovery.Discovery
		pubSub                  PublishSubscriber
		searchEngine            search.IndexSearcher
		blockchain              blockchain.Interface
		dataQueryProtocol       dataquery.Interface
		blockDownloaderProtocol blockdownloader.Interface
		config                  *ffgconfig.Config
		expErr                  string
	}{
		"no config": {
			expErr: "config is nil",
		},
		"no host": {
			config: &ffgconfig.Config{},
			expErr: "host is nil",
		},
		"no dht": {
			config: &ffgconfig.Config{},
			host:   h,
			expErr: "dht is nil",
		},
		"no discovery": {
			config: &ffgconfig.Config{},
			host:   h,
			dht:    kademliaDHT,
			expErr: "discovery is nil",
		},
		"no search": {
			config:    &ffgconfig.Config{},
			host:      h,
			dht:       kademliaDHT,
			discovery: &drouting.RoutingDiscovery{},
			expErr:    "search is nil",
		},
		"no pubSub": {
			config:       &ffgconfig.Config{},
			host:         h,
			dht:          kademliaDHT,
			discovery:    &drouting.RoutingDiscovery{},
			searchEngine: &search.BleveSearch{},
			expErr:       "pubSub is nil",
		},
		"no blockchain": {
			config:       &ffgconfig.Config{},
			host:         h,
			dht:          kademliaDHT,
			discovery:    &drouting.RoutingDiscovery{},
			searchEngine: &search.BleveSearch{},
			pubSub:       &pubsub.PubSub{},
			expErr:       "blockchain is nil",
		},
		"no dataquery": {
			config:       &ffgconfig.Config{},
			host:         h,
			dht:          kademliaDHT,
			discovery:    &drouting.RoutingDiscovery{},
			searchEngine: &search.BleveSearch{},
			pubSub:       &pubsub.PubSub{},
			blockchain:   &blockchain.Blockchain{},
			expErr:       "dataQuery is nil",
		},
		"no blockDownloader": {
			config:            &ffgconfig.Config{},
			host:              h,
			dht:               kademliaDHT,
			discovery:         &drouting.RoutingDiscovery{},
			searchEngine:      &search.BleveSearch{},
			pubSub:            &pubsub.PubSub{},
			blockchain:        &blockchain.Blockchain{},
			dataQueryProtocol: dataQueryProtocol,
			expErr:            "blockDownloader is nil",
		},
		"success": {
			config:                  &ffgconfig.Config{},
			host:                    h,
			dht:                     kademliaDHT,
			discovery:               &drouting.RoutingDiscovery{},
			searchEngine:            &search.BleveSearch{},
			pubSub:                  &pubsub.PubSub{},
			blockchain:              &blockchain.Blockchain{},
			dataQueryProtocol:       dataQueryProtocol,
			blockDownloaderProtocol: &blockdownloader.Protocol{},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			node, err := New(tt.config, tt.host, tt.dht, tt.discovery, tt.pubSub, tt.searchEngine, tt.blockchain, tt.dataQueryProtocol, tt.blockDownloaderProtocol)
			if tt.expErr != "" {
				assert.Nil(t, node)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, node)
			}
		})
	}
}

func TestProtobufMessage(t *testing.T) {
	// block
	payload := messages.GossipPayload{
		Message: &messages.GossipPayload_Blocks{Blocks: &messages.ProtoBlocks{Blocks: []*block.ProtoBlock{}}},
	}
	msg := payload.GetMessage()
	switch msg.(type) {
	case *messages.GossipPayload_Blocks:
	case *messages.GossipPayload_Transaction:
		assert.Fail(t, "shouldnt be a transaction")
	case *messages.GossipPayload_Query:
		assert.Fail(t, "shouldnt be a query")
	}

	// tx
	payload = messages.GossipPayload{
		Message: &messages.GossipPayload_Transaction{
			Transaction: &transaction.ProtoTransaction{Hash: []byte{2}},
		},
	}
	msg = payload.GetMessage()
	switch msg.(type) {
	case *messages.GossipPayload_Blocks:
		assert.Fail(t, "shouldnt be a block")
	case *messages.GossipPayload_Transaction:
	case *messages.GossipPayload_Query:
		assert.Fail(t, "shouldnt be a query")
	}

	// query
	payload = messages.GossipPayload{
		Message: &messages.GossipPayload_Query{Query: &messages.DataQueryRequestProto{}},
	}
	msg = payload.GetMessage()
	switch msg.(type) {
	case *messages.GossipPayload_Blocks:
		assert.Fail(t, "shouldnt be a block")
	case *messages.GossipPayload_Transaction:
		assert.Fail(t, "shouldnt be a transaction")
	case *messages.GossipPayload_Query:
	}

	// message is nil and not of any type
	payload = messages.GossipPayload{}
	msg = payload.GetMessage()
	switch msg.(type) {
	case *messages.GossipPayload_Blocks:
		assert.Fail(t, "shouldnt be a block")
	case *messages.GossipPayload_Transaction:
		assert.Fail(t, "shouldnt be a transaction")
	case *messages.GossipPayload_Query:
		assert.Fail(t, "shouldnt be a query")
	}
}

func TestGetMultiAddrFromString(t *testing.T) {
	_, err := GetMultiAddrFromString("wrongaddr")
	assert.EqualError(t, err, "failed to validate multiaddr: failed to parse multiaddr \"wrongaddr\": must begin with /")

	strMultiAddr := "/ip4/0.0.0.0/tcp/65513/p2p/16Uiu2HAm2edbaX9YyMauXDjdhcdF34P59zg29xtP9nmeS7MJNbxo"
	validAddr, err := GetMultiAddrFromString(strMultiAddr)
	assert.NoError(t, err)
	assert.Equal(t, strMultiAddr, validAddr.String())
}

func TestBootstrap(t *testing.T) {
	ctx := context.Background()
	n1 := createNode(t, "6558", "bootstrapdb.bin", "bootstrapdbchain.bin")
	n2 := createNode(t, "6557", "bootstrapdb2.bin", "bootstrapdbchain2.bin")
	t.Cleanup(func() {
		n1.searchEngine.Close()
		n2.searchEngine.Close()

		// nolint:errcheck
		n1.blockchain.CloseDB()
		// nolint:errcheck
		n2.blockchain.CloseDB()

		os.RemoveAll("bootstrapdb.bin")
		os.RemoveAll("bootstrapdb2.bin")

		os.RemoveAll("bootstrapdbchain.bin")
		os.RemoveAll("bootstrapdbchain2.bin")
	})
	err := n1.Bootstrap(ctx, []string{})
	assert.NoError(t, err)
	addr, err := n1.GetMultiaddr()
	assert.NoError(t, err)

	err = n2.Bootstrap(ctx, []string{addr[0].String()})
	assert.NoError(t, err)
	n2peers := n2.Peers()

	// we should make sure n1 was bootstrapped.
	assert.Contains(t, n2peers.String(), n1.GetID())
}

func TestNodeMethods(t *testing.T) {
	ctx := context.Background()
	n1 := createNode(t, "65512", "node1search.bin", "mainchaindb1.bin")
	n2 := createNode(t, "65513", "node2search.bin", "mainchaindb2.bin")
	n3 := createNode(t, "65514", "node3search.bin", "mainchaindb3.bin")

	assert.Equal(t, uint64(0), n1.blockchain.GetHeight())
	assert.Equal(t, uint64(0), n2.blockchain.GetHeight())
	assert.Equal(t, uint64(0), n3.blockchain.GetHeight())

	t.Cleanup(func() {
		n1.searchEngine.Close()
		n2.searchEngine.Close()
		n3.searchEngine.Close()

		// nolint:errcheck
		n1.blockchain.CloseDB()
		// nolint:errcheck
		n2.blockchain.CloseDB()
		// nolint:errcheck
		n3.blockchain.CloseDB()

		os.RemoveAll("node1search.bin")
		os.RemoveAll("node2search.bin")
		os.RemoveAll("node3search.bin")

		os.RemoveAll("mainchaindb1.bin")
		os.RemoveAll("mainchaindb2.bin")
		os.RemoveAll("mainchaindb3.bin")
	})

	ns := "randevouz"
	// Advertise
	n1.Advertise(ctx, ns)
	n2.Advertise(ctx, ns)
	n3.Advertise(ctx, ns)

	// Bootstrap
	err := n1.Bootstrap(ctx, []string{})
	assert.NoError(t, err)
	err = n2.Bootstrap(ctx, []string{})
	assert.NoError(t, err)
	err = n3.Bootstrap(ctx, []string{})
	assert.NoError(t, err)

	// GetMultiaddr
	p1addr, err := n1.GetMultiaddr()
	assert.NoError(t, err)

	p2addr, err := n2.GetMultiaddr()
	assert.NoError(t, err)

	// GetPeerID
	pid1 := n1.GetPeerID()

	// ConnectToPeerWithMultiaddr

	// invalid multiAddr
	_, err = n2.ConnectToPeerWithMultiaddr(context.Background(), &multiaddr.Component{})
	assert.EqualError(t, err, "failed to get info from p2p addr: invalid p2p multiaddr")

	// valid multiaddr but node is offline
	strMultiAddr := "/ip4/0.0.0.0/tcp/6555/p2p/16Uiu2HAm2edbaX9YyMauXDjdhcdF34P59zg29xtP9nmeS7MJNbxo"
	validAddr, err := GetMultiAddrFromString(strMultiAddr)
	assert.NoError(t, err)
	_, err = n2.ConnectToPeerWithMultiaddr(context.Background(), validAddr)
	assert.ErrorContains(t, err, "failed to connect to host: failed to dial 16Uiu2HAm2edbaX9YyMauXDjdhcdF34P59zg29xtP9nmeS7MJNbxo")

	_, err = n2.ConnectToPeerWithMultiaddr(context.Background(), p1addr[0])
	assert.NoError(t, err)
	_, err = n3.ConnectToPeerWithMultiaddr(context.Background(), p2addr[0])
	assert.NoError(t, err)

	// DiscoverPeers
	err = n1.DiscoverPeers(ctx, ns)
	assert.NoError(t, err)
	err = n2.DiscoverPeers(ctx, ns)
	assert.NoError(t, err)
	err = n3.DiscoverPeers(ctx, ns)
	assert.NoError(t, err)

	// Publish before the gossip network is active
	err = n3.PublishMessageToNetwork(ctx, []byte("should fail"))
	assert.EqualError(t, err, "pubsub topic is not available")

	// HandleIncomingMessages
	err = n1.HandleIncomingMessages(ctx, "randevouz")
	assert.NoError(t, err)
	// second time
	err = n1.HandleIncomingMessages(ctx, "randevouz")
	assert.EqualError(t, err, "already subscribed to topic")

	err = n2.HandleIncomingMessages(ctx, "randevouz")
	assert.NoError(t, err)
	err = n3.HandleIncomingMessages(ctx, "randevouz")
	assert.NoError(t, err)

	// add delay just to propagate the changes to the nodes.
	time.Sleep(100 * time.Millisecond)

	// FindPeers
	info := n3.FindPeers(context.Background(), []peer.ID{pid1})
	assert.NotEmpty(t, info)

	// check the peerstores are not empty
	assert.Len(t, n1.Peers(), 3)
	assert.Len(t, n2.Peers(), 4) // this should be 4 because we tried to connect to an invalid host
	assert.Len(t, n3.Peers(), 3)

	// node3 publishes a message to network
	// PublishMessageToNetwork
	err = n3.PublishMessageToNetwork(ctx, []byte("hello world"))
	time.Sleep(100 * time.Millisecond)
	assert.NoError(t, err)

	// send an invalid transaction to the network
	tx := transaction.Transaction{
		Hash: []byte{1},
		From: "0x2",
	}

	payload := messages.GossipPayload{
		Message: &messages.GossipPayload_Transaction{Transaction: transaction.ToProtoTransaction(tx)},
	}
	blockData, err := proto.Marshal(&payload)
	assert.NoError(t, err)
	err = n3.PublishMessageToNetwork(ctx, blockData)
	assert.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	// mempool should be empty
	transactions := n1.blockchain.GetTransactionsFromPool()
	assert.Empty(t, transactions)

	// create a valid transaction and propagate to network
	validtx, _ := validTransaction(t)
	payload = messages.GossipPayload{
		Message: &messages.GossipPayload_Transaction{Transaction: transaction.ToProtoTransaction(*validtx)},
	}
	blockData, err = proto.Marshal(&payload)
	assert.NoError(t, err)

	err = n3.PublishMessageToNetwork(ctx, blockData)
	assert.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	// mempool should not be empty
	transactions = n1.blockchain.GetTransactionsFromPool()
	assert.NotEmpty(t, transactions)

	// send an invalid block to the network
	blk := block.Block{
		Hash: []byte{1},
	}
	payload = messages.GossipPayload{
		Message: &messages.GossipPayload_Blocks{Blocks: &messages.ProtoBlocks{Blocks: []*block.ProtoBlock{block.ToProtoBlock(blk)}}},
	}
	blockData, err = proto.Marshal(&payload)
	assert.NoError(t, err)
	err = n3.PublishMessageToNetwork(ctx, blockData)
	assert.NoError(t, err)
	time.Sleep(200 * time.Millisecond)

	// blockpool should be empty
	blockPoolData := n1.blockchain.GetBlocksFromPool()
	assert.Empty(t, blockPoolData)

	// valid block is broadcasted and the other nodes blockchain has been updated
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)
	validBlock, kp := validBlock(t)
	validBlock.PreviousBlockHash = genesisblockValid.Hash
	block.SetBlockVerifiers(block.Verifier{Address: kp.Address})
	err = validBlock.Sign(kp.PrivateKey)
	assert.NoError(t, err)
	payload = messages.GossipPayload{
		Message: &messages.GossipPayload_Blocks{Blocks: &messages.ProtoBlocks{Blocks: []*block.ProtoBlock{block.ToProtoBlock(*validBlock)}}},
	}
	blockData, err = proto.Marshal(&payload)
	assert.NoError(t, err)
	err = n3.PublishMessageToNetwork(ctx, blockData)
	assert.NoError(t, err)
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, uint64(1), n1.blockchain.GetHeight())
}

func newHost(t *testing.T, port string) host.Host {
	priv, _, err := crypto.GenerateKeyPair(crypto.Secp256k1, 256)
	assert.NoError(t, err)
	connManager, err := connmgr.NewConnManager(
		100,
		400,
		connmgr.WithGracePeriod(time.Minute),
	)
	assert.NoError(t, err)

	host, err := libp2p.New(libp2p.Identity(priv),
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/127.0.0.1/tcp/%s", port)),
		libp2p.Ping(false),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),
		libp2p.DefaultTransports,
		libp2p.ConnectionManager(connManager),
		libp2p.NATPortMap(),
		libp2p.EnableNATService(),
	)
	assert.NoError(t, err)
	return host
}

func createNode(t *testing.T, port string, searchDB string, blockchainDBPath string) *Node {
	bgCtx := context.Background()
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)
	genesisHash := make([]byte, len(genesisblockValid.Hash))
	copy(genesisHash, genesisblockValid.Hash)

	host := newHost(t, port)
	kademliaDHT, err := dht.New(bgCtx, host, dht.Mode(dht.ModeServer))
	assert.NoError(t, err)
	err = kademliaDHT.Bootstrap(bgCtx)
	assert.NoError(t, err)
	routingDiscovery := drouting.NewRoutingDiscovery(kademliaDHT)
	blv, err := search.NewBleveSearch(searchDB)
	assert.NoError(t, err)
	searchEngine, err := search.New(blv)
	assert.NoError(t, err)

	optsPS := []pubsub.Option{
		pubsub.WithMessageSigning(true),
		pubsub.WithMaxMessageSize(10 * pubsub.DefaultMaxMessageSize),
	}
	gossip, err := pubsub.NewGossipSub(bgCtx, host, optsPS...)
	assert.NoError(t, err)

	db, err := leveldb.OpenFile(blockchainDBPath, nil)
	assert.NoError(t, err)

	blockchainDB, err := database.New(db)
	assert.NoError(t, err)

	bchain, err := blockchain.New(blockchainDB, genesisHash)
	assert.NoError(t, err)

	err = bchain.InitOrLoad()
	assert.NoError(t, err)

	dataQueryProtocol, err := dataquery.New(host)
	assert.NoError(t, err)

	blockDownloader, err := blockdownloader.New(bchain, host)
	assert.NoError(t, err)

	node, err := New(&ffgconfig.Config{}, host, kademliaDHT, routingDiscovery, gossip, searchEngine, bchain, dataQueryProtocol, blockDownloader)
	assert.NoError(t, err)
	return node
}

func validTransaction(t *testing.T) (*transaction.Transaction, ffgcrypto.KeyPair) {
	const chainID = "0x01"

	keypair, err := ffgcrypto.GenerateKeyPair()
	assert.NoError(t, err)

	pkyData, err := keypair.PublicKey.Raw()
	assert.NoError(t, err)

	mainChain, err := hexutil.Decode(chainID)
	assert.NoError(t, err)

	addr, err := ffgcrypto.RawPublicToAddress(pkyData)
	assert.NoError(t, err)

	tx := transaction.Transaction{
		PublicKey:       pkyData,
		Nounce:          []byte{0},
		Data:            []byte{1},
		From:            addr,
		To:              addr,
		Chain:           mainChain,
		Value:           "0x22b1c8c1227a00000",
		TransactionFees: "0x0",
	}
	err = tx.Sign(keypair.PrivateKey)
	assert.NoError(t, err)
	return &tx, keypair
}

// generate a block and propagate the keypair used for the tx
func validBlock(t *testing.T) (*block.Block, ffgcrypto.KeyPair) {
	validTx, kp := validTransaction(t)
	b := block.Block{
		Timestamp:         time.Now().Unix(),
		Data:              []byte{1},
		PreviousBlockHash: []byte{1, 1},
		Transactions: []transaction.Transaction{
			// its a coinbase tx
			*validTx,
		},
		Number: 1,
	}

	return &b, kp
}
