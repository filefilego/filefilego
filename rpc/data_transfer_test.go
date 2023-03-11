package rpc

import (
	"context"
	"testing"

	dataquery "github.com/filefilego/filefilego/node/protocols/data_query"
	dataverification "github.com/filefilego/filefilego/node/protocols/data_verification"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
)

func TestNewDataTransferAPI(t *testing.T) {
	t.Parallel()
	h := newHost(t, "2391")
	cases := map[string]struct {
		host                     host.Host
		dataQueryProtocol        dataquery.Interface
		dataVerificationProtocol dataverification.Interface
		publisherNodesFinder     PublisherNodesFinder
		expErr                   string
	}{
		"no host": {
			expErr: "host is nil",
		},
		"no data query": {
			host:   h,
			expErr: "data query protocol is nil",
		},
		"no data verification": {
			host:              h,
			dataQueryProtocol: &dataquery.Protocol{},
			expErr:            "data verification protocol is nil",
		},
		"no publisherNodeFinder": {
			host:                     h,
			dataQueryProtocol:        &dataquery.Protocol{},
			dataVerificationProtocol: &dataverification.Protocol{},
			expErr:                   "publisherNodeFinder is nil",
		},
		"success": {
			host:                     h,
			dataQueryProtocol:        &dataquery.Protocol{},
			dataVerificationProtocol: &dataverification.Protocol{},
			publisherNodesFinder:     &networkMessagePublisherNodesFinderStub{},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, err := NewDataTransferAPI(tt.host, tt.dataQueryProtocol, tt.dataVerificationProtocol, tt.publisherNodesFinder)
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

type networkMessagePublisherNodesFinderStub struct {
	err       error
	addrInfos []peer.AddrInfo
}

func (n *networkMessagePublisherNodesFinderStub) PublishMessageToNetwork(ctx context.Context, data []byte) error {
	return n.err
}

func (n *networkMessagePublisherNodesFinderStub) FindPeers(ctx context.Context, peerIDs []peer.ID) []peer.AddrInfo {
	return n.addrInfos
}
