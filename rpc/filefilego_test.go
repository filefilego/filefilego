package rpc

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	block "github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common/hexutil"
	ffgconfig "github.com/filefilego/filefilego/config"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/database"
	"github.com/filefilego/filefilego/node"
	blockdownloader "github.com/filefilego/filefilego/node/protocols/block_downloader"
	dataquery "github.com/filefilego/filefilego/node/protocols/data_query"
	"github.com/filefilego/filefilego/search"
	"github.com/filefilego/filefilego/storage"
	transaction "github.com/filefilego/filefilego/transaction"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestNewFilefilegoAPI(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		node       node.Interface
		blockchain blockchain.Interface
		expErr     string
	}{
		"no node": {
			expErr: "node is nil",
		},
		"no blockchain": {
			node:   &node.Node{},
			expErr: "blockchain is nil",
		},
		"success": {
			node:       &node.Node{},
			blockchain: &blockchain.Blockchain{},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, err := NewFilefilegoAPI(tt.node, tt.blockchain)
			if tt.expErr != "" {
				assert.Nil(t, api)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, api)
				assert.NoError(t, err)
			}
		})
	}
}

func TestFilefilegoAPIMethods(t *testing.T) {
	ctx := context.Background()
	n1, bhcain1, se1 := createNode(t, "65512", "node1search.bin", "mainchaindb1.bin")
	n2, bhcain2, se2 := createNode(t, "65513", "node2search.bin", "mainchaindb2.bin")

	assert.Equal(t, uint64(0), bhcain1.GetHeight())
	assert.Equal(t, uint64(0), bhcain2.GetHeight())

	t.Cleanup(func() {
		se1.Close()
		se2.Close()

		// nolint:errcheck
		bhcain1.CloseDB()
		// nolint:errcheck
		bhcain2.CloseDB()

		os.RemoveAll("node1search.bin")
		os.RemoveAll("node2search.bin")

		os.RemoveAll("mainchaindb1.bin")
		os.RemoveAll("mainchaindb2.bin")
	})

	ns := "randevouz"
	// Advertise
	n1.Advertise(ctx, ns)
	n2.Advertise(ctx, ns)

	// Bootstrap
	err := n1.Bootstrap(ctx, []string{})
	assert.NoError(t, err)
	err = n2.Bootstrap(ctx, []string{})
	assert.NoError(t, err)

	// GetMultiaddr
	p1addr, err := n1.GetMultiaddr()
	assert.NoError(t, err)

	_, err = n2.ConnectToPeerWithMultiaddr(context.Background(), p1addr[0])
	assert.NoError(t, err)

	// DiscoverPeers
	err = n1.DiscoverPeers(ctx, ns)
	assert.NoError(t, err)
	err = n2.DiscoverPeers(ctx, ns)
	assert.NoError(t, err)

	// add one block to the first blockchain
	genBlock, err := block.GetGenesisBlock()
	assert.NoError(t, err)
	validBlock2, kp, _ := validBlock(t, 1)
	validBlock2.PreviousBlockHash = make([]byte, len(genBlock.Hash))
	copy(validBlock2.PreviousBlockHash, genBlock.Hash)

	err = validBlock2.Sign(kp.PrivateKey)
	assert.NoError(t, err)
	pubKeyBytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)
	block.SetBlockVerifiers(block.Verifier{
		Address:   kp.Address,
		PublicKey: hexutil.Encode(pubKeyBytes),
	})
	err = bhcain1.PerformStateUpdateFromBlock(*validBlock2)
	assert.NoError(t, err)

	api, err := NewFilefilegoAPI(n1, bhcain1)
	assert.NoError(t, err)
	assert.NotNil(t, api)

	api2, err := NewFilefilegoAPI(n2, bhcain2)
	assert.NoError(t, err)
	assert.NotNil(t, api2)

	response := &StatusResponse{}
	err = api.Status(&http.Request{}, &EmptyArgs{}, response)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), response.BlockchainHeight)
	assert.Equal(t, 2, response.PeerCount)
	assert.Equal(t, n1.GetID(), response.PeerID)
	assert.NotEmpty(t, response.Verifiers)

	response2 := &StatusResponse{}
	err = api2.Status(&http.Request{}, &EmptyArgs{}, response2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), response2.BlockchainHeight)
	assert.Equal(t, 2, response2.PeerCount)
	assert.Equal(t, n2.GetID(), response2.PeerID)
	assert.NotEmpty(t, response2.Verifiers)
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

func createNode(t *testing.T, port string, searchDB string, blockchainDBPath string) (*node.Node, *blockchain.Blockchain, *search.Search) {
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

	bchain, err := blockchain.New(blockchainDB, &search.Search{}, genesisHash)
	assert.NoError(t, err)

	err = bchain.InitOrLoad()
	assert.NoError(t, err)

	dataQueryProtocol, err := dataquery.New(host)
	assert.NoError(t, err)

	blockDownloader, err := blockdownloader.New(bchain, host)
	assert.NoError(t, err)

	node, err := node.New(&ffgconfig.Config{}, host, kademliaDHT, routingDiscovery, gossip, searchEngine, &storage.Storage{}, bchain, dataQueryProtocol, blockDownloader)
	assert.NoError(t, err)
	return node, bchain, searchEngine
}

// generate a block and propagate the keypair used for the tx
func validBlock(t *testing.T, blockNumber uint64) (*block.Block, ffgcrypto.KeyPair, ffgcrypto.KeyPair) {
	coinbasetx, kp := validTransaction(t)
	err := coinbasetx.Sign(kp.PrivateKey)
	assert.NoError(t, err)

	validTx2, kp2 := validTransaction(t)
	validTx2.PublicKey, err = kp.PublicKey.Raw()
	assert.NoError(t, err)
	validTx2.From = kp.Address
	validTx2.To = kp2.Address
	validTx2.TransactionFees = "0x1"
	validTx2.Value = "0x1"
	validTx2.Nounce = []byte{1}
	err = validTx2.Sign(kp.PrivateKey)
	assert.NoError(t, err)

	b := block.Block{
		Timestamp:         time.Now().Unix(),
		Data:              []byte{1},
		PreviousBlockHash: []byte{1, 1},
		Transactions: []transaction.Transaction{
			// its a coinbase tx
			*coinbasetx,
			*validTx2,
		},
		Number: blockNumber,
	}

	return &b, kp, kp2
}

// generate a keypair and use it to sign tx
func validTransaction(t *testing.T) (*transaction.Transaction, ffgcrypto.KeyPair) {
	keypair, err := ffgcrypto.GenerateKeyPair()
	assert.NoError(t, err)

	pkyData, err := keypair.PublicKey.Raw()
	assert.NoError(t, err)

	mainChain, err := hexutil.Decode("0x01")
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
	assert.NoError(t, err)
	return &tx, keypair
}
