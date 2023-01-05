package node

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/filefilego/filefilego/internal/search"
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
)

func TestNew(t *testing.T) {
	t.Parallel()

	h := newHost(t, "1032")
	kademliaDHT, err := dht.New(context.Background(), h, dht.Mode(dht.ModeServer))
	assert.NoError(t, err)

	cases := map[string]struct {
		host         host.Host
		dht          PeerFinderBootstrapper
		discovery    libp2pdiscovery.Discovery
		pubSub       PublishSubscriber
		searchEngine search.IndexSearcher
		expErr       string
	}{
		"no host": {
			expErr: "host is nil",
		},
		"no dht": {
			host:   h,
			expErr: "dht is nil",
		},
		"no discovery": {
			host:   h,
			dht:    kademliaDHT,
			expErr: "discovery is nil",
		},
		"no search": {
			host:      h,
			dht:       kademliaDHT,
			discovery: &drouting.RoutingDiscovery{},
			expErr:    "search is nil",
		},
		"no pubSub": {
			host:         h,
			dht:          kademliaDHT,
			discovery:    &drouting.RoutingDiscovery{},
			searchEngine: &search.BleveSearch{},
			expErr:       "pubSub is nil",
		},
		"success": {
			host:         h,
			dht:          kademliaDHT,
			discovery:    &drouting.RoutingDiscovery{},
			searchEngine: &search.BleveSearch{},
			pubSub:       &pubsub.PubSub{},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			node, err := New(tt.host, tt.dht, tt.discovery, tt.pubSub, tt.searchEngine)
			if tt.expErr != "" {
				assert.Nil(t, node)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, node)
			}
		})
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
	n1 := createNode(t, "6558", "bootstrapdb.bin")
	n2 := createNode(t, "6557", "bootstrapdb2.bin")
	t.Cleanup(func() {
		n1.searchEngine.Close()
		n2.searchEngine.Close()

		os.RemoveAll("bootstrapdb.bin")
		os.RemoveAll("bootstrapdb2.bin")
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

	n1 := createNode(t, "65512", "node1search.bin")
	n2 := createNode(t, "65513", "node2search.bin")
	n3 := createNode(t, "65514", "node3search.bin")
	t.Cleanup(func() {
		n1.searchEngine.Close()
		n2.searchEngine.Close()
		n3.searchEngine.Close()

		os.RemoveAll("node1search.bin")
		os.RemoveAll("node2search.bin")
		os.RemoveAll("node3search.bin")
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
	assert.NoError(t, err)
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
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", port)),
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

func createNode(t *testing.T, port string, searchDB string) *Node {
	bgCtx := context.Background()

	host := newHost(t, port)
	kademliaDHT, err := dht.New(bgCtx, host, dht.Mode(dht.ModeServer))
	assert.NoError(t, err)
	err = kademliaDHT.Bootstrap(bgCtx)
	assert.NoError(t, err)
	routingDiscovery := drouting.NewRoutingDiscovery(kademliaDHT)
	blv, err := search.NewBleeveSearch(searchDB)
	assert.NoError(t, err)
	searchEngine, err := search.New(blv)
	assert.NoError(t, err)

	optsPS := []pubsub.Option{
		pubsub.WithMessageSigning(true),
		pubsub.WithMaxMessageSize(10 * pubsub.DefaultMaxMessageSize),
	}
	gossip, err := pubsub.NewGossipSub(bgCtx, host, optsPS...)
	assert.NoError(t, err)

	node, err := New(host, kademliaDHT, routingDiscovery, gossip, searchEngine)
	assert.NoError(t, err)
	return node
}
