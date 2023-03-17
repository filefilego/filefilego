package rpc

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/search"
)

// ChannelAPI represents the channel rpc service.
type ChannelAPI struct {
	blockchain blockchain.Interface
	search     search.IndexSearcher
}

// NewChannelAPI creates a new channel API to be served using JSONRPC.
func NewChannelAPI(bchain blockchain.Interface, search search.IndexSearcher) (*ChannelAPI, error) {
	if bchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	if search == nil {
		return nil, errors.New("search is nil")
	}

	return &ChannelAPI{
		blockchain: bchain,
		search:     search,
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

// GetNodeItemArgs is a response.
type GetNodeItemArgs struct {
	NodeHash string `json:"node_hash"`
}

// GetNodeItemResponse is a response.
type GetNodeItemResponse struct {
	Node *blockchain.NodeItem `json:"node"`
}

// GetNodeItem gets a node item.
func (api *ChannelAPI) GetNodeItem(r *http.Request, args *GetNodeItemArgs, response *GetNodeItemResponse) error {
	nodeHashBytes, err := hexutil.Decode(args.NodeHash)
	if err != nil {
		return fmt.Errorf("failed to decode node hash: %w", err)
	}

	item, err := api.blockchain.GetNodeItem(nodeHashBytes)
	if err != nil {
		return fmt.Errorf("failed to find node: %w", err)
	}

	response.Node = item

	return nil
}

// FilesFromEntryOrFolderArgs is a request.
type FilesFromEntryOrFolderArgs struct {
	NodeHash string `json:"node_hash"`
}

// FilesFromEntryOrFolderResponse is a response.
type FilesFromEntryOrFolderResponse struct {
	Files []blockchain.FileMetadata `json:"files"`
}

// FilesFromEntryOrFolder all the files of a node which is a dir or an entry recursvely.
func (api *ChannelAPI) FilesFromEntryOrFolder(r *http.Request, args *FilesFromEntryOrFolderArgs, response *FilesFromEntryOrFolderResponse) error {
	nodeHashBytes, err := hexutil.Decode(args.NodeHash)
	if err != nil {
		return fmt.Errorf("failed to decode node hash: %w", err)
	}

	files, err := api.blockchain.GetFilesFromEntryOrFolderRecursively(nodeHashBytes)
	if err != nil {
		return fmt.Errorf("failed to find files in the requested node: %w", err)
	}

	response.Files = make([]blockchain.FileMetadata, len(files))
	copy(response.Files, files)

	return nil
}
