package node

import (
	"github.com/libp2p/go-libp2p-core/crypto"
)

// Verifier represents a block verifier/sealer
type Verifier struct {
	Address         string `json:"address"`
	InitialBalance  string `json:"initial_balance"`
	PublicKey       string `json:"public_key"`
	DataVerifier    bool   `json:"data_verifier"`
	PublicKeyCrypto crypto.PubKey
}

var (
	// BlockSealers are the sealers
	BlockSealers []Verifier
)
