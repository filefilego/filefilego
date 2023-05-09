package rpc

import (
	"testing"

	"github.com/filefilego/filefilego/node"
	storageprotocol "github.com/filefilego/filefilego/node/protocols/storage"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/stretchr/testify/assert"
)

func TestNewStorageAPI(t *testing.T) {
	t.Parallel()
	h := newHost(t, "6691")
	cases := map[string]struct {
		host            host.Host
		publisher       NetworkMessagePublisher
		storageProtocol storageprotocol.Interface
		expErr          string
	}{
		"no host": {
			expErr: "host is nil",
		},
		"no publisher": {
			host:   h,
			expErr: "publisher is nil",
		},
		"no storageProtocol": {
			host:      h,
			publisher: &node.Node{},
			expErr:    "storageProtocol is nil",
		},
		"success": {
			host:            h,
			publisher:       &node.Node{},
			storageProtocol: &storageprotocol.Protocol{},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, err := NewStorageAPI(tt.host, tt.publisher, tt.storageProtocol)
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
