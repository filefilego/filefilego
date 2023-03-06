package rpc

import (
	"testing"

	"github.com/filefilego/filefilego/blockchain"
	dataquery "github.com/filefilego/filefilego/node/protocols/data_query"
	"github.com/filefilego/filefilego/search"
	"github.com/filefilego/filefilego/storage"
	"github.com/stretchr/testify/assert"
)

func TestNewChannelAPI(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		blockchain        blockchain.Interface
		search            search.IndexSearcher
		storage           storage.Interface
		dataQueryProtocol dataquery.Interface
		expErr            string
	}{
		"no blockchain": {
			expErr: "blockchain is nil",
		},
		"no search": {
			blockchain: &blockchain.Blockchain{},
			expErr:     "search is nil",
		},
		"no storage": {
			blockchain: &blockchain.Blockchain{},
			search:     &search.BleveSearch{},
			expErr:     "storage is nil",
		},
		"no dataQueryProtocol": {
			blockchain: &blockchain.Blockchain{},
			search:     &search.BleveSearch{},
			storage:    &storage.Storage{},
			expErr:     "data query protocol is nil",
		},
		"success": {
			blockchain:        &blockchain.Blockchain{},
			search:            &search.BleveSearch{},
			storage:           &storage.Storage{},
			dataQueryProtocol: &dataquery.Protocol{},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, err := NewChannelAPI(tt.blockchain, tt.search, tt.storage, tt.dataQueryProtocol)
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
