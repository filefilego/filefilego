package config

import (
	"flag"
	"testing"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func TestNew(t *testing.T) {
	ctx := cli.NewContext(cli.NewApp(), &flag.FlagSet{}, &cli.Context{})
	config := New(ctx)
	assert.NotNil(t, config)

	conf := &Config{
		Global: global{
			SearchEngineResultCount:                 100,
			StorageFileMerkleTreeTotalSegments:      1024,
			StorageFileSegmentsEncryptionPercentage: 1,
		},
		RPC: rpc{
			Whitelist:       []string{},
			EnabledServices: []string{},
			DisabledMethods: []string{},
			HTTP: httpWSConfig{
				Enabled:          false,
				ListenPort:       8090,
				ListenAddress:    "127.0.0.1",
				CrossOriginValue: "*",
			},
			Websocket: httpWSConfig{
				Enabled:          false,
				ListenPort:       8091,
				ListenAddress:    "127.0.0.1",
				CrossOriginValue: "*",
			},
			Socket: unixDomainSocket{
				Enabled: false,
				Path:    "",
			},
		},
		P2P: p2p{
			GossipMaxMessageSize: 10 * pubsub.DefaultMaxMessageSize,
			MinPeers:             100,
			MaxPeers:             400,
			ListenPort:           10209,
			ListenAddress:        "127.0.0.1",
		},
	}
	assert.Equal(t, conf, config)
}
