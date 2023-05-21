package dataquery

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/stretchr/testify/assert"
)

func TestDataQueryProtocol(t *testing.T) {
	h1, privKey1, pubkey1 := newHost(t, "7965")
	h2, _, _ := newHost(t, "7966")
	h3, _, _ := newHost(t, "7963")

	protocol1, err := New(nil)
	assert.EqualError(t, err, "host is nil")
	assert.Nil(t, protocol1)

	protocol1, err = New(h1)
	assert.NoError(t, err)
	protocol2, err := New(h2)
	assert.NoError(t, err)

	protocol3, err := New(h3)
	assert.NoError(t, err)
	assert.NotNil(t, protocol3)

	peer2Info := peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: h2.Addrs(),
	}

	err = h1.Connect(context.Background(), peer2Info)
	assert.NoError(t, err)

	err = h3.Connect(context.Background(), peer2Info)
	assert.NoError(t, err)

	dqrequest := messages.DataQueryRequest{
		FileHashes:   [][]byte{{12}},
		FromPeerAddr: h1.ID().String(),
		Timestamp:    time.Now().Unix(),
	}

	hashOfReq := dqrequest.GetHash()
	dqrequest.Hash = make([]byte, len(hashOfReq))
	copy(dqrequest.Hash, hashOfReq)

	err = protocol2.PutQueryHistory(hexutil.Encode(hashOfReq), dqrequest)
	assert.NoError(t, err)
	pkbytes, err := pubkey1.Raw()
	assert.NoError(t, err)
	pmsg := messages.DataQueryResponseProto{
		FeesPerByte:           "0x1",
		FileHashes:            [][]byte{{12}},
		UnavailableFileHashes: [][]byte{},
		Timestamp:             time.Now().Unix(),
		PublicKey:             pkbytes,
		HashDataQueryRequest:  hashOfReq,
		FromPeerAddr:          h1.ID().Pretty(),
	}

	dqr := messages.ToDataQueryResponse(&pmsg)
	sig, err := messages.SignDataQueryResponse(privKey1, dqr)
	assert.NoError(t, err)
	dqr.Signature = make([]byte, len(sig))
	pmsg.Signature = make([]byte, len(sig))
	copy(pmsg.Signature, sig)
	copy(dqr.Signature, sig)

	err = protocol1.SendDataQueryResponse(context.TODO(), h2.ID(), &pmsg)
	assert.NoError(t, err)
	err = protocol1.SendDataQueryResponse(context.TODO(), h2.ID(), &pmsg)
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)
	msgs, ok := protocol2.GetQueryResponse(hexutil.Encode(hashOfReq))
	assert.True(t, ok)
	assert.NotEmpty(t, msgs)

	dqrequestold := messages.DataQueryRequest{
		FileHashes:   [][]byte{{12}},
		FromPeerAddr: h1.ID().String(),
		Timestamp:    time.Now().Unix(),
	}
	hashOfOldReq := dqrequestold.GetHash()
	dqrequestold.Hash = make([]byte, len(hashOfOldReq))
	copy(dqrequestold.Hash, hashOfOldReq)
	err = protocol2.PutQueryHistory(hexutil.Encode(hashOfOldReq), dqrequestold)
	assert.NoError(t, err)
	req, ok := protocol2.GetQueryHistory(hexutil.Encode(hashOfOldReq))
	assert.Equal(t, true, ok)
	req.Timestamp = req.Timestamp - ((dataQueryReqAgeToPurgeInMins + 1) * 60)
	err = protocol2.PurgeQueryHistory()
	assert.NoError(t, err)
	assert.Len(t, protocol2.queryHistory, 1)

	err = protocol3.RequestDataQueryResponseTransfer(context.TODO(), h2.ID(), &messages.DataQueryResponseTransferProto{Hash: hashOfReq})
	assert.NoError(t, err)
	results, ok := protocol3.GetQueryResponse(hexutil.Encode(hashOfReq))
	assert.True(t, ok)
	assert.Len(t, results, 1)
	assert.Equal(t, results[0], dqr)
}

func TestVerifyDataFromPeer(t *testing.T) {
	data := []byte{1}
	sig := []byte{1}
	pubKey := []byte{1}
	// invalid data
	err := VerifyDataFromPeer(data, sig, peer.NewPeerRecord().PeerID, pubKey)
	assert.EqualError(t, err, "failed to extrac public key: malformed public key: invalid length: 1")

	host, _, _ := newHost(t, "2049")
	pubKeybytes, err := host.Peerstore().PubKey(host.ID()).Raw()
	assert.NoError(t, err)
	err = VerifyDataFromPeer(data, sig, peer.NewPeerRecord().PeerID, pubKeybytes)
	assert.EqualError(t, err, "peerID doesn't match the ID derived from publicKey")

	err = VerifyDataFromPeer(data, sig, host.ID(), pubKeybytes)
	assert.EqualError(t, err, "failed to verify signature: malformed signature: too short: 1 < 8")

	privKey := host.Peerstore().PrivKey(host.ID())

	signature, err := privKey.Sign(data)
	assert.NoError(t, err)

	// valid data
	err = VerifyDataFromPeer(data, signature, host.ID(), pubKeybytes)
	assert.NoError(t, err)
}

func newHost(t *testing.T, port string) (host.Host, crypto.PrivKey, crypto.PubKey) {
	priv, pubKey, err := crypto.GenerateKeyPair(crypto.Secp256k1, 256)
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
	return host, priv, pubKey
}
