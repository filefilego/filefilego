package rpc

import (
	"errors"
	"net/http"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/config"
	"github.com/filefilego/filefilego/node"
)

// FilefilegoAPI represents the filefilego rpc service.
type FilefilegoAPI struct {
	conf       *config.Config
	node       node.Interface
	blockchain blockchain.Interface
}

// NewFilefilegoAPI creates a new filefilego API to be served using JSONRPC.
func NewFilefilegoAPI(cfg *config.Config, node node.Interface, blockchain blockchain.Interface) (*FilefilegoAPI, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}

	if node == nil {
		return nil, errors.New("node is nil")
	}

	if blockchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	return &FilefilegoAPI{
		conf:       cfg,
		node:       node,
		blockchain: blockchain,
	}, nil
}

// StatsResponse represents a syncing status
type StatsResponse struct {
	Syncing          bool       `json:"syncing"`
	BlockchainHeight uint64     `json:"blockchain_height"`
	PeerCount        int        `json:"peer_count"`
	PeerID           string     `json:"peer_id"`
	StorageEnabled   bool       `json:"storage_enabled"`
	Verifiers        []verifier `json:"verifiers"`
}

type verifier struct {
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
}

// Stats reports the stats of the node.
func (api *FilefilegoAPI) Stats(r *http.Request, args *EmptyArgs, response *StatsResponse) error {
	response.Syncing = api.node.GetSyncing()
	response.BlockchainHeight = api.blockchain.GetHeight()
	response.PeerCount = api.node.Peers().Len()
	response.PeerID = api.node.GetID()
	response.StorageEnabled = api.conf.Global.Storage
	allVerifiers := block.GetBlockVerifiers()
	response.Verifiers = make([]verifier, len(allVerifiers))

	for i, v := range allVerifiers {
		response.Verifiers[i] = verifier{
			Address:   v.Address,
			PublicKey: v.PublicKey,
		}
	}

	return nil
}
