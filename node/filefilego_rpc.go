package node

import (
	"context"
)

// FilefilegoAPI represents the ffg service
type FilefilegoAPI struct {
	Node *Node
}

// NewFilefilegoAPI new instance of the service
func NewFilefilegoAPI(node *Node) *FilefilegoAPI {
	return &FilefilegoAPI{Node: node}
}

// FilefilegoResult ...
type FilefilegoResult struct {
	IsSyncing    bool   `json:"is_syncing"`
	CurrentBlock uint64 `json:"current_block"`
}

// Syncing checks if client is syncing
func (api *FilefilegoAPI) Syncing(ctx context.Context) (FilefilegoResult, error) {
	dt := FilefilegoResult{
		IsSyncing:    api.Node.GetSyncing(),
		CurrentBlock: api.Node.BlockChain.GetHeight(),
	}
	return dt, nil
}

// BlockchainHeight gets current blockchain height
func (api *FilefilegoAPI) BlockchainHeight(ctx context.Context) (uint64, error) {
	return api.Node.BlockChain.GetHeight(), nil
}

// PeerCount counts of peers on this node
func (api *FilefilegoAPI) PeerCount(ctx context.Context) (int, error) {
	return api.Node.Peers().Len(), nil
}

// Verifier list of the first verifier
func (api *FilefilegoAPI) Verifier(ctx context.Context) (string, error) {
	return api.Node.GetBlockchainSettings().Verifiers[0].Address, nil
}

// Settings returns current settings of the network
func (api *FilefilegoAPI) Settings(ctx context.Context) (NodeSettings, error) {
	return api.Node.GetNodeSettings(), nil
}

// PeerID returns the current node peer ID
func (api *FilefilegoAPI) PeerID(ctx context.Context) (string, error) {
	return api.Node.Host.ID().String(), nil
}
