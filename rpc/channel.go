package rpc

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/search"
	"github.com/filefilego/filefilego/transaction"
	"google.golang.org/protobuf/proto"
)

const (
	orderAsc  = "asc"
	orderDesc = "desc"
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
	CurrentPage int    `json:"current_page"`
	PageSize    int    `json:"page_size"`
	Order       string `json:"order"`
}

// ListResponse is a list response.
type ListResponse struct {
	Total       uint64         `json:"total"`
	CurrentPage int            `json:"current_page"`
	PageSize    int            `json:"page_size"`
	Channels    []NodeItemJSON `json:"channels"`
}

// List returns a list of channels.
func (api *ChannelAPI) List(r *http.Request, args *ListArgs, response *ListResponse) error {
	if args.Order != orderAsc && args.Order != orderDesc {
		return fmt.Errorf("invalid order: %s", args.Order)
	}

	channels, err := api.blockchain.GetChannels(args.CurrentPage, args.PageSize, args.Order)
	if err != nil {
		return fmt.Errorf("failed to get channels list: %w", err)
	}
	response.Total = api.blockchain.GetChannelsCount()
	response.CurrentPage = args.CurrentPage
	response.PageSize = args.PageSize
	response.Channels = make([]NodeItemJSON, len(channels))
	for i, v := range channels {
		response.Channels[i] = transformNodeItemToJSON(v)
	}
	return nil
}

// CreateNodeItemsTxDataPayloadArgs is a create channel node item request payload.
type CreateNodeItemsTxDataPayloadArgs struct {
	Nodes []NodeItemJSON `json:"nodes"`
}

// CreateNodeItemsTxDataPayloadResponse is a response which contains the transaction data payload for creating the channel node items.
// It contains the required fees for creating the provided node items based on their type.
type CreateNodeItemsTxDataPayloadResponse struct {
	TransactionDataPayloadHex string `json:"transaction_data_payload_hex"`
	TotalFeesRequired         string `json:"total_fees_required"`
}

// CreateNodeItemsTxDataPayload a channel node items that returns the transaction data payload, which in turn can be used in a transaction data payload.
func (api *ChannelAPI) CreateNodeItemsTxDataPayload(r *http.Request, args *CreateNodeItemsTxDataPayloadArgs, response *CreateNodeItemsTxDataPayloadResponse) error {
	if len(args.Nodes) == 0 {
		return errors.New("empty node items")
	}

	nodesEnvelope := blockchain.NodeItems{
		Nodes: make([]*blockchain.NodeItem, 0),
	}

	for _, v := range args.Nodes {
		item := blockchain.NodeItem{
			Name:       v.Name,
			Enabled:    v.Enabled,
			NodeType:   blockchain.NodeItemType(v.NodeType),
			Timestamp:  v.Timestamp,
			Admins:     make([][]byte, 0),
			Posters:    make([][]byte, 0),
			Attributes: make([][]byte, 0),
		}

		if v.NodeHash != "" {
			nodeHash, err := hexutil.Decode(v.NodeHash)
			if err != nil {
				return fmt.Errorf("failed to decode node hash: %w", err)
			}
			item.NodeHash = nodeHash
		}

		if v.ParentHash != "" {
			parentHash, err := hexutil.Decode(v.ParentHash)
			if err != nil {
				return fmt.Errorf("failed to decode parent hash: %w", err)
			}
			item.ParentHash = parentHash
		}

		if v.Owner != "" {
			owner, err := hexutil.Decode(v.Owner)
			if err != nil {
				return fmt.Errorf("failed to decode owner: %w", err)
			}
			item.Owner = owner
		}

		if v.MerkleRoot != "" {
			merkleRoot, err := hexutil.Decode(v.MerkleRoot)
			if err != nil {
				return fmt.Errorf("failed to decode merkle root hash: %w", err)
			}
			item.MerkleRoot = merkleRoot
		}

		if v.FileHash != "" {
			if strings.HasPrefix(v.FileHash, "0x") {
				fileHash, err := hexutil.Decode(v.FileHash)
				if err != nil {
					return fmt.Errorf("failed to decode file hash: %w", err)
				}
				item.FileHash = fileHash
			} else {
				fileHash, err := hexutil.DecodeNoPrefix(v.FileHash)
				if err != nil {
					return fmt.Errorf("failed to decode file hash: %w", err)
				}
				item.FileHash = fileHash
			}
		}

		if v.ContentType != "" {
			item.ContentType = &v.ContentType
		}

		if v.Description != "" {
			item.Description = &v.Description
		}

		if v.Size != 0 {
			item.Size = &v.Size
		}

		for _, v := range v.Admins {
			adm, err := hexutil.Decode(v)
			if err != nil {
				return fmt.Errorf("failed to decode admin address: %w", err)
			}
			item.Admins = append(item.Admins, adm)
		}

		for _, v := range v.Posters {
			poster, err := hexutil.Decode(v)
			if err != nil {
				return fmt.Errorf("failed to decode poster address: %w", err)
			}
			item.Posters = append(item.Posters, poster)
		}

		for _, v := range v.Attributes {
			item.Attributes = append(item.Attributes, []byte(v))
		}

		nodesEnvelope.Nodes = append(nodesEnvelope.Nodes, &item)
	}

	totalFeesRequired := blockchain.CalculateChannelActionsFees(nodesEnvelope.Nodes)
	nodeEnvelopeBytes, err := proto.Marshal(&nodesEnvelope)
	if err != nil {
		return fmt.Errorf("failed to marshal nodes envelope: %w", err)
	}

	dataPayload := transaction.DataPayload{
		Type:    transaction.DataType_CREATE_NODE,
		Payload: make([]byte, len(nodeEnvelopeBytes)),
	}

	copy(dataPayload.Payload, nodeEnvelopeBytes)

	dataPayloadBytes, err := proto.Marshal(&dataPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction data payload: %w", err)
	}

	response.TransactionDataPayloadHex = hexutil.Encode(dataPayloadBytes)
	response.TotalFeesRequired = hexutil.EncodeBig(totalFeesRequired)

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
	Nodes []NodeItemJSON `json:"nodes"`
}

// Search search in nodes.
func (api *ChannelAPI) Search(r *http.Request, args *SearchArgs, response *SearchResponse) error {
	nodeHashes, err := api.search.Search(r.Context(), args.Query, args.Size, args.CurrentPage, search.Type(args.SearchType))
	if err != nil {
		return fmt.Errorf("failed to perform search: %w", err)
	}

	response.Nodes = make([]NodeItemJSON, 0)

	for _, v := range nodeHashes {
		nodeHash, err := hexutil.Decode(v)
		if err != nil {
			continue
		}
		node, err := api.blockchain.GetNodeItem(nodeHash)
		if err != nil {
			continue
		}
		response.Nodes = append(response.Nodes, transformNodeItemToJSON(node))
	}

	return nil
}

// GetNodeItemArgs is a response.
type GetNodeItemArgs struct {
	NodeHash    string `json:"node_hash"`
	CurrentPage int    `json:"current_page"`
	PageSize    int    `json:"page_size"`
	Order       string `json:"order"`
	// ChildNodeItemsType denotes which types to be included in the node child items.
	ChildNodeItemsType   string `json:"child_node_items_type"`
	ExcludeChildItemType string `json:"exclude_child_item_type"`
}

// NodeItemJSON represents a node item json.
type NodeItemJSON struct {
	Name        string         `json:"name"`
	NodeHash    string         `json:"node_hash"`
	Owner       string         `json:"owner"`
	Enabled     bool           `json:"enabled"`
	NodeType    int32          `json:"node_type"`
	Attributes  []string       `json:"attributes"`
	Admins      []string       `json:"admins"`
	Posters     []string       `json:"posters"`
	Timestamp   int64          `json:"timestamp"`
	Description string         `json:"description"`
	MerkleRoot  string         `json:"merkle_root"`
	FileHash    string         `json:"file_hash"`
	Size        uint64         `json:"size"`
	ParentHash  string         `json:"parent_hash"`
	ContentType string         `json:"content_type"`
	Nodes       []NodeItemJSON `json:"nodes"`
}

// GetNodeItemResponse is a response.
type GetNodeItemResponse struct {
	Node            NodeItemJSON `json:"node"`
	TotalChildNodes uint64       `json:"total_child_nodes"`
}

// GetNodeItem gets a node item.
func (api *ChannelAPI) GetNodeItem(r *http.Request, args *GetNodeItemArgs, response *GetNodeItemResponse) error {
	nodeHashBytes, err := hexutil.Decode(args.NodeHash)
	if err != nil {
		return fmt.Errorf("failed to decode node hash: %w", err)
	}

	if args.Order != orderAsc && args.Order != orderDesc {
		args.Order = orderAsc
	}

	item, err := api.blockchain.GetNodeItem(nodeHashBytes)
	if err != nil {
		return fmt.Errorf("failed to find node: %w", err)
	}

	response.Node = transformNodeItemToJSON(item)

	childs, totalChilds, err := api.blockchain.GetChildNodeItems(item.NodeHash, args.CurrentPage, args.PageSize, args.Order, args.ChildNodeItemsType, args.ExcludeChildItemType)
	if err == nil {
		response.TotalChildNodes = totalChilds
		response.Node.Nodes = make([]NodeItemJSON, len(childs))
		for i, v := range childs {
			response.Node.Nodes[i] = transformNodeItemToJSON(v)
		}
	}

	return nil
}

// FilesFromEntryOrFolderArgs is a request.
type FilesFromEntryOrFolderArgs struct {
	NodeHash    string `json:"node_hash"`
	CurrentPage int    `json:"current_page"`
	PageSize    int    `json:"page_size"`
	Order       string `json:"order"`
}

// FileMetadata represents a file metadata
type FileMetadata struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
	Size uint64 `json:"size"`
	Path string `json:"path"`
}

// FilesFromEntryOrFolderResponse is a response.
type FilesFromEntryOrFolderResponse struct {
	Files []FileMetadata `json:"files"`
}

// FilesFromEntryOrFolder all the files of a node which is a dir or an entry recursvely.
func (api *ChannelAPI) FilesFromEntryOrFolder(r *http.Request, args *FilesFromEntryOrFolderArgs, response *FilesFromEntryOrFolderResponse) error {
	nodeHashBytes, err := hexutil.Decode(args.NodeHash)
	if err != nil {
		return fmt.Errorf("failed to decode node hash: %w", err)
	}

	if args.Order != orderAsc && args.Order != orderDesc {
		args.Order = orderAsc
	}

	files, err := api.blockchain.GetFilesFromEntryOrFolderRecursively(nodeHashBytes, args.CurrentPage, args.PageSize, args.Order)
	if err != nil {
		return fmt.Errorf("failed to find files in the requested node: %w", err)
	}

	response.Files = make([]FileMetadata, len(files))
	for i, v := range files {
		response.Files[i] = FileMetadata{
			Name: v.Name,
			Hash: v.Hash,
			Size: v.Size,
			Path: v.Path,
		}
	}

	return nil
}

func transformNodeItemToJSON(item *blockchain.NodeItem) NodeItemJSON {
	transformed := NodeItemJSON{
		Name:       item.Name,
		NodeHash:   hexutil.Encode(item.NodeHash),
		Owner:      hexutil.Encode(item.Owner),
		Enabled:    item.Enabled,
		NodeType:   int32(item.NodeType),
		Timestamp:  item.Timestamp,
		MerkleRoot: hexutil.Encode(item.MerkleRoot),
		FileHash:   hexutil.EncodeNoPrefix(item.FileHash),
		ParentHash: hexutil.Encode(item.ParentHash),
		Attributes: make([]string, len(item.Attributes)),
		Admins:     make([]string, len(item.Admins)),
		Posters:    make([]string, len(item.Posters)),
	}

	if item.Description != nil {
		transformed.Description = *item.Description
	}

	if item.Size != nil {
		transformed.Size = *item.Size
	}

	if item.ContentType != nil {
		transformed.ContentType = *item.ContentType
	}

	for i, v := range item.Attributes {
		transformed.Attributes[i] = string(v)
	}

	for i, v := range item.Admins {
		transformed.Admins[i] = hexutil.Encode(v)
	}

	for i, v := range item.Posters {
		transformed.Posters[i] = hexutil.Encode(v)
	}

	return transformed
}
