package rpc

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/config"
	"github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/node"
	"github.com/libp2p/go-libp2p/core/host"
)

// FilefilegoAPI represents the filefilego rpc service.
type FilefilegoAPI struct {
	conf       *config.Config
	node       node.Interface
	blockchain blockchain.Interface
	host       host.Host
}

// NewFilefilegoAPI creates a new filefilego API to be served using JSONRPC.
func NewFilefilegoAPI(cfg *config.Config, node node.Interface, blockchain blockchain.Interface, host host.Host) (*FilefilegoAPI, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}

	if node == nil {
		return nil, errors.New("node is nil")
	}

	if blockchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	if host == nil {
		return nil, errors.New("host is nil")
	}

	return &FilefilegoAPI{
		conf:       cfg,
		node:       node,
		blockchain: blockchain,
		host:       host,
	}, nil
}

// StatsResponse represents a syncing status
type StatsResponse struct {
	Syncing                       bool       `json:"syncing"`
	BlockchainHeight              uint64     `json:"blockchain_height"`
	HeighestBlockNumberDiscovered uint64     `json:"heighest_block_number_discovered"`
	PeerCount                     int        `json:"peer_count"`
	PeerID                        string     `json:"peer_id"`
	StorageEnabled                bool       `json:"storage_enabled"`
	Verifiers                     []verifier `json:"verifiers"`
}

type verifier struct {
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
}

// Stats reports the stats of the node.
func (api *FilefilegoAPI) Stats(r *http.Request, args *EmptyArgs, response *StatsResponse) error {
	response.Syncing = api.node.GetSyncing()
	response.HeighestBlockNumberDiscovered = api.node.HeighestBlockNumberDiscovered()
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

// HostInfoResponse represents a response.
type HostInfoResponse struct {
	PeerID    string `json:"peer_id"`
	Address   string `json:"address"`
	PeerCount int    `json:"peer_count"`
}

// HostInfo returns the node's addresses.
func (api *FilefilegoAPI) HostInfo(r *http.Request, args *EmptyArgs, response *HostInfoResponse) error {
	response.PeerCount = api.node.Peers().Len()
	publicKey := api.host.Peerstore().PubKey(api.host.ID())
	publicKeyBytes, err := publicKey.Raw()
	if err != nil {
		return fmt.Errorf("failed to get public key bytes: %w", err)
	}
	nodeAddress, err := crypto.RawPublicToAddress(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to get address from public key bytes: %w", err)
	}
	response.Address = nodeAddress
	response.PeerID = api.node.GetID()

	return nil
}
