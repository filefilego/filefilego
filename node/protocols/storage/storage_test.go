package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/filefilego/filefilego/common"
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

func TestStorageProtocol(t *testing.T) {
	h1, _, pubKey := newHost(t, "7365")
	h2, _, _ := newHost(t, "7366")

	protocol1, err := New(nil, true)
	assert.EqualError(t, err, "host is nil")
	assert.Nil(t, protocol1)

	protocol1, err = New(h1, true)
	assert.NoError(t, err)
	assert.NotNil(t, protocol1)
	protocol2, err := New(h2, true)
	assert.NoError(t, err)
	assert.NotNil(t, protocol2)

	peer2Info := peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: h2.Addrs(),
	}

	err = h1.Connect(context.Background(), peer2Info)
	assert.NoError(t, err)

	timePassed, err := protocol1.TestSpeedWithRemotePeer(context.TODO(), h2.ID(), 10*common.MB)
	assert.NoError(t, err)
	ms1, err := time.ParseDuration("1ms")
	assert.NoError(t, err)
	assert.Greater(t, timePassed, ms1)

	pubKeyBytes, err := pubKey.Raw()
	assert.NoError(t, err)

	response := &messages.StorageQueryResponseProto{
		StorageProviderPeerAddr: h1.ID().Pretty(),
		Location:                "US",
		FeesPerByte:             "0x01",
		PublicKey:               pubKeyBytes,
	}

	data := bytes.Join(
		[][]byte{
			[]byte(response.StorageProviderPeerAddr),
			[]byte(response.Location),
			[]byte(response.FeesPerByte),
			response.PublicKey,
		},
		[]byte{},
	)

	h := sha256.New()
	if _, err := h.Write(data); err != nil {
		assert.NoError(t, err)
	}
	hash := h.Sum(nil)
	privateKey := h1.Peerstore().PrivKey(h1.ID())
	sig, err := privateKey.Sign(hash)
	assert.NoError(t, err)

	response.Hash = make([]byte, len(hash))
	response.Signature = make([]byte, len(sig))

	copy(response.Hash, hash)
	copy(response.Signature, sig)

	err = protocol1.SendStorageQueryResponse(context.TODO(), h2.ID(), response)
	assert.NoError(t, err)
	err = protocol1.SendStorageQueryResponse(context.TODO(), h2.ID(), response)
	assert.NoError(t, err)

	time.Sleep(1 * time.Second)
	providers := protocol2.GetDiscoveredStorageProviders()
	assert.Len(t, providers, 1)
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
