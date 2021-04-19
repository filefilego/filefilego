package node

import (
	"github.com/filefilego/filefilego/common/hexutil"
)

var (
	BlockchainChainID = hexutil.MustDecode("0x01")
)

// BlockchainSettings represents starting point of the blockchain
type BlockchainSettings struct {
	BinLayerEngineEnabled    bool       `json:"binlayer_engine_enabled"`
	BlockchainVersion        string     `json:"blockchain_version"`
	Chain                    []byte     `json:"chain"`
	GenesisHash              string     `json:"genesis_hash"`
	BlockTimeSeconds         int        `json:"block_time_seconds"`
	InitialBlockReward       string     `json:"initial_block_reward"`
	MaxSupply                string     `json:"max_supply"`
	DropRewardDays           int        `json:"drop_reward_days"`
	DropRewardFactor         int        `json:"drop_reward_factor"`
	NamespaceEnabled         bool       `json:"namespace_enabled"`
	NamespaceRegistrationFee string     `json:"namespace_registration_fee"`
	NodeCreationFeesGuest    string     `json:"node_creation_fees_guest"`
	Verifiers                []Verifier `json:"verifiers"`
}

// GetBlockchainSettings returns the genesis data
func (n *Node) GetBlockchainSettings() BlockchainSettings {

	gen := BlockchainSettings{
		BinLayerEngineEnabled: n.BinLayerEngine.Enabled,
		BlockchainVersion:     "0.9.3",
		Chain:                 BlockchainChainID, // 1 for Mainnet, anything else for other chains
		GenesisHash:           "c2005c6ea44df4800bbd56d857bb6cb727acde486869553d212056bea38438e9",
		BlockTimeSeconds:      10,
		InitialBlockReward:    "15000000000000000000",        // 15 zarans
		MaxSupply:             "500000000000000000000000000", // 500M zarans
		DropRewardDays:        730,                           //2 years
		DropRewardFactor:      2,
		NamespaceEnabled:      true,
		//NamespaceRegistrationFee: "10000000000000000000000", //10k zarans
		NamespaceRegistrationFee: "15000000000000000000", //15 zarans
		NodeCreationFeesGuest:    "1000000000000000000",  //1 Zaran
		Verifiers: []Verifier{
			{
				Address:        "0xcfc954667d85b9ff0a29093df130b1249bb743f1",
				InitialBalance: "0",
				PublicKey:      "0x0327ee3ce92a07f46a47c2ebfe960444af034c6066bbb68488bce64e29f6c0c03e",
				DataVerifier:   false,
			},
			{
				Address:        "0x7469627e6b6b44c3e55fb3dc5f73291f3199b55e",
				InitialBalance: "0",
				PublicKey:      "0x03610d11f98d804c2c14acf8ec2941b3057b811fd533966c380709dcce3779f570",
				DataVerifier:   true,
			},
			{
				Address:        "0xbeb23dabb05d9eb619c163aa659938bdb9f37925",
				InitialBalance: "0",
				PublicKey:      "0x0342db44d08ea94d06a32e62d481fb4fd5c7d82cd55dedde9b3ba107f9f0c41107",
				DataVerifier:   true,
			},
			{
				Address:        "0xf2e61e373525380dfb9f8ae5caf90789fbd28216",
				InitialBalance: "0",
				PublicKey:      "0x0365dfaf14b84923e2f57e65e0a73838225a7da5a4be418931efccbe9ef827ab90",
				DataVerifier:   true,
			},
			{
				Address:        "0x94358081e866b83e307d8312693f9820dcb02663",
				InitialBalance: "0",
				PublicKey:      "0x03d61458c7103ef84bc1afe05d402ebc6a8309146f85ac42c3632bc9c41f9e6288",
				DataVerifier:   true,
			},
		},
	}
	return gen
}
