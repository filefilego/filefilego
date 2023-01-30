package rpc

import (
	"errors"
	"net/http"

	"github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/blockchain"
	"github.com/filefilego/filefilego/internal/node"
)

// FilefilegoAPI represents the filefilego rpc service.
type FilefilegoAPI struct {
	node       node.Interface
	blockchain blockchain.Interface
}

// NewFilefilegoAPI creates a new filefilego API to be served using JSONRPC.
func NewFilefilegoAPI(node node.Interface, blockchain blockchain.Interface) (*FilefilegoAPI, error) {
	if node == nil {
		return nil, errors.New("node is nil")
	}

	if blockchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	return &FilefilegoAPI{
		node:       node,
		blockchain: blockchain,
	}, nil
}

// SyncingResponse represents a syncing status
type StatusResponse struct {
	Syncing          bool       `json:"syncing"`
	BlockchainHeight uint64     `json:"blockchain_height"`
	PeerCount        int        `json:"peer_count"`
	PeerID           string     `json:"peer_id"`
	Verifiers        []verifier `json:"verifiers"`
}

type verifier struct {
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
}

// Status reports the status of the node.
func (api *FilefilegoAPI) Status(r *http.Request, args *EmptyArgs, response *StatusResponse) error {
	response.Syncing = api.node.GetSyncing()
	response.BlockchainHeight = api.blockchain.GetHeight()
	response.PeerCount = api.node.Peers().Len()
	response.PeerID = api.node.GetID()
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
