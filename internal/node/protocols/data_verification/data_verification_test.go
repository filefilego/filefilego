package dataverification

import (
	"fmt"
	"testing"
	"time"

	"github.com/filefilego/filefilego/internal/contract"
	"github.com/filefilego/filefilego/internal/database"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	connmgr "github.com/libp2p/go-libp2p/p2p/net/connmgr"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	t.Parallel()
	h, _, _ := newHost(t, "1134")
	t.Cleanup(func() {
		h.Close()
	})

	c, err := contract.New(&database.DB{})
	assert.NoError(t, err)

	cases := map[string]struct {
		host          host.Host
		contractStore contract.Interface
		expErr        string
	}{
		"no host": {
			expErr: "host is nil",
		},
		"no contract store": {
			host:   h,
			expErr: "contract store is nil",
		},
		"success": {
			host:          h,
			contractStore: c,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			protocol, err := New(tt.host, tt.contractStore)
			if tt.expErr != "" {
				assert.Nil(t, protocol)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, protocol)
			}
		})
	}
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
