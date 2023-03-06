package rpc

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common/hexutil"
	dataquery "github.com/filefilego/filefilego/node/protocols/data_query"
	"github.com/filefilego/filefilego/search"
	"github.com/filefilego/filefilego/storage"
)

// ChannelAPI represents the channel rpc service.
type ChannelAPI struct {
	blockchain        blockchain.Interface
	search            search.IndexSearcher
	storage           storage.Interface
	dataQueryProtocol dataquery.Interface
}

// NewChannelAPI creates a new channel API to be served using JSONRPC.
func NewChannelAPI(bchain blockchain.Interface, search search.IndexSearcher, storage storage.Interface, dataQueryProtocol dataquery.Interface) (*ChannelAPI, error) {
	if bchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	if search == nil {
		return nil, errors.New("search is nil")
	}

	if storage == nil {
		return nil, errors.New("storage is nil")
	}

	if dataQueryProtocol == nil {
		return nil, errors.New("data query protocol is nil")
	}

	return &ChannelAPI{
		blockchain:        bchain,
		search:            search,
		storage:           storage,
		dataQueryProtocol: dataQueryProtocol,
	}, nil
}

// ListArgs is a list args
type ListArgs struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// ListResponse is a list response.
type ListResponse struct {
	Total    uint64                 `json:"total"`
	Limit    int                    `json:"limit"`
	Offset   int                    `json:"offset"`
	Channels []*blockchain.NodeItem `json:"channels"`
}

// List returns a list of channels.
func (api *ChannelAPI) List(r *http.Request, args *ListArgs, response *ListResponse) error {
	channels, err := api.blockchain.GetChannels(args.Limit, args.Offset)
	if err != nil {
		return fmt.Errorf("failed to get channels list: %w", err)
	}

	response.Total = api.blockchain.GetChannelsCount()
	response.Limit = args.Limit
	response.Offset = args.Offset
	response.Channels = channels
	return nil
}

// SearchArgs is a search args.
type SearchArgs struct {
	Query       string `json:"query"`
	SearchType  string `json:"search_type"`
	Size        int    `json:"size"`
	CurrentPage int    `json:"current_page"`
}

// SearchResponse is a response with the search results.
type SearchResponse struct {
	Nodes []*blockchain.NodeItem `json:"nodes"`
}

// Search search in nodes.
func (api *ChannelAPI) Search(r *http.Request, args *SearchArgs, response *SearchResponse) error {
	nodeHashes, err := api.search.Search(r.Context(), args.Query, args.Size, args.CurrentPage, search.Type(args.SearchType))
	if err != nil {
		return fmt.Errorf("failed to perform search: %w", err)
	}

	for _, v := range nodeHashes {
		nodeHash, err := hexutil.Decode(v)
		if err != nil {
			continue
		}
		node, err := api.blockchain.GetNodeItem(nodeHash)
		if err != nil {
			continue
		}
		response.Nodes = append(response.Nodes, node)
	}

	return nil
}
