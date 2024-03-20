package blockdownloader

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common/hexutil"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/database"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/filefilego/filefilego/search"
	"github.com/filefilego/filefilego/transaction"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestNew(t *testing.T) {
	t.Parallel()

	h := newHost(t, "1134")
	t.Cleanup(func() {
		h.Close()
		os.RemoveAll("blockchain.db")
	})
	cases := map[string]struct {
		blockchain blockchain.Interface
		host       host.Host
		expErr     string
	}{
		"no blockchain": {
			expErr: "blockchain is nil",
		},
		"no host": {
			blockchain: &blockchain.Blockchain{},
			expErr:     "host is nil",
		},
		"success": {
			blockchain: &blockchain.Blockchain{},
			host:       h,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			protocol, err := New(tt.blockchain, tt.host)
			if tt.expErr != "" {
				assert.Nil(t, protocol)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, protocol)
			}
		})
	}
}

func TestProtocolMethods(t *testing.T) {
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)
	db, err := leveldb.OpenFile("blockchain1.db", nil)
	assert.NoError(t, err)
	db2, err := leveldb.OpenFile("blockchain2.db", nil)
	assert.NoError(t, err)
	db3, err := leveldb.OpenFile("blockchain3.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	driver2, err := database.New(db)
	assert.NoError(t, err)
	driver3, err := database.New(db)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		db2.Close()
		db3.Close()
		os.RemoveAll("blockchain1.db")
		os.RemoveAll("blockchain2.db")
		os.RemoveAll("blockchain3.db")
	})

	// blockchain 1
	bchain1, err := blockchain.New(driver, &search.Search{}, genesisblockValid.Hash)
	assert.NoError(t, err)
	assert.NotNil(t, bchain1)
	err = bchain1.InitOrLoad(true)
	assert.NoError(t, err)

	// blockchain 2
	bchain2, err := blockchain.New(driver2, &search.Search{}, genesisblockValid.Hash)
	assert.NoError(t, err)
	assert.NotNil(t, bchain2)
	err = bchain2.InitOrLoad(true)
	assert.NoError(t, err)

	// blockchain 3
	bchain3, err := blockchain.New(driver3, &search.Search{}, genesisblockValid.Hash)
	assert.NoError(t, err)
	assert.NotNil(t, bchain3)
	err = bchain3.InitOrLoad(true)
	assert.NoError(t, err)

	validBlock2, kp, _ := validBlock(t, 1)
	validBlock2.PreviousBlockHash = make([]byte, len(genesisblockValid.Hash))
	copy(validBlock2.PreviousBlockHash, genesisblockValid.Hash)

	err = validBlock2.Sign(kp.PrivateKey)
	assert.NoError(t, err)
	pubKeyBytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)
	block.SetBlockVerifiers(block.Verifier{
		Address:   kp.Address,
		PublicKey: hexutil.Encode(pubKeyBytes),
	})
	err = bchain1.PerformStateUpdateFromBlock(*validBlock2)
	assert.NoError(t, err)
	block2ByHeight, err := bchain1.GetBlockByNumber(1)
	assert.NoError(t, err)
	assert.EqualValues(t, validBlock2.Hash, block2ByHeight.Hash)

	h1 := newHost(t, "1139")
	h2 := newHost(t, "1149")
	h3 := newHost(t, "1169")

	peer1Info := peer.AddrInfo{
		ID:    h1.ID(),
		Addrs: h1.Addrs(),
	}

	peer3Info := peer.AddrInfo{
		ID:    h3.ID(),
		Addrs: h3.Addrs(),
	}

	err = h2.Connect(context.TODO(), peer1Info)
	assert.NoError(t, err)
	err = h2.Connect(context.TODO(), peer3Info)
	assert.NoError(t, err)

	protocol1, err := New(bchain1, h1)
	assert.NoError(t, err)
	assert.NotNil(t, protocol1)

	protocol2, err := New(bchain2, h2)
	assert.NoError(t, err)
	assert.NotNil(t, protocol2)

	protocol3, err := New(bchain3, h3)
	assert.NoError(t, err)
	assert.NotNil(t, protocol3)

	// GetRemotePeers is empty
	assert.Len(t, protocol1.GetRemotePeers(), 0)

	nextPeer, err := protocol1.GetNextPeer()
	assert.EqualError(t, err, "no peers in the list")
	assert.Nil(t, nextPeer)

	// AddRemotePeer
	remoteFromH2ToH1, err := NewRemotePeer(h2, h1.ID())
	assert.NoError(t, err)
	remoteFromH2ToH3, err := NewRemotePeer(h2, h3.ID())
	assert.NoError(t, err)

	protocol2.AddRemotePeer(remoteFromH2ToH1)
	// dupe
	protocol2.AddRemotePeer(remoteFromH2ToH1)
	assert.Len(t, protocol2.GetRemotePeers(), 1)

	// add another peer
	protocol2.AddRemotePeer(remoteFromH2ToH3)
	assert.Len(t, protocol2.GetRemotePeers(), 2)

	// should return first peer
	nextPeer, err = protocol2.GetNextPeer()
	assert.NoError(t, err)
	assert.Equal(t, remoteFromH2ToH1.peer, nextPeer.peer)

	// should return second peer
	nextPeer, err = protocol2.GetNextPeer()
	assert.NoError(t, err)
	assert.Equal(t, remoteFromH2ToH3.peer, nextPeer.peer)

	// should return again first peer because of the round
	nextPeer, err = protocol2.GetNextPeer()
	assert.NoError(t, err)
	assert.Equal(t, remoteFromH2ToH1.peer, nextPeer.peer)

	// RemoveRemotePeer
	protocol2.RemoveRemotePeer(remoteFromH2ToH1)
	assert.Len(t, protocol2.GetRemotePeers(), 1)

	// add the peer back to protocol2
	protocol2.AddRemotePeer(remoteFromH2ToH1)
	assert.Len(t, protocol2.GetRemotePeers(), 2)

	// second peer should be there
	assert.Equal(t, remoteFromH2ToH3.peer, protocol2.GetRemotePeers()[0].peer)

	// GetHeight
	responseFromH1, err := remoteFromH2ToH1.GetHeight(context.TODO())
	assert.NoError(t, err)
	assert.NotNil(t, responseFromH1)
	assert.Equal(t, uint64(1), remoteFromH2ToH1.CurrentHeight())

	responseFromH3, err := remoteFromH2ToH3.GetHeight(context.TODO())
	assert.NoError(t, err)
	assert.NotNil(t, responseFromH3)
	assert.Equal(t, uint64(0), remoteFromH2ToH3.CurrentHeight())

	// the longest block will be 1 which is held by h1
	assert.Equal(t, uint64(1), protocol2.GetHeighestBlockNumberFromPeers())

	// DownloadBlocksRange
	blockRequestPayload := &messages.BlockDownloadRequestProto{
		From: 1,
		To:   1,
	}
	blockResponseFromh1, err := remoteFromH2ToH1.DownloadBlocksRange(context.TODO(), blockRequestPayload)
	assert.NoError(t, err)
	assert.NotNil(t, blockResponseFromh1)
	assert.Equal(t, false, blockResponseFromh1.Error)
	assert.Len(t, blockResponseFromh1.Blocks, 1)
	assert.Equal(t, uint64(1), blockResponseFromh1.Blocks[0].Number)

	protocol2.Reset()
	assert.Len(t, protocol2.GetRemotePeers(), 0)
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

// generate a block and propagate the keypair used for the tx
func validBlock(t *testing.T, blockNumber uint64) (*block.Block, ffgcrypto.KeyPair, ffgcrypto.KeyPair) {
	coinbasetx, kp := validTransaction(t)
	err := coinbasetx.Sign(kp.PrivateKey)
	assert.NoError(t, err)

	validTx2, kp2 := validTransaction(t)

	pubkeybytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)
	validTx2 = transaction.NewTransaction(transaction.LegacyTxType, pubkeybytes, []byte{1}, validTx2.Data(), kp.Address, kp2.Address, "0x1", "0x1", validTx2.Chain())
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

	tx := transaction.NewTransaction(transaction.LegacyTxType, pkyData, []byte{0}, []byte{1}, addr, addr, "0x22b1c8c1227a00000", "0x0", mainChain)

	assert.NoError(t, err)
	return tx, keypair
}
