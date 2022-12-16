package block

import "github.com/libp2p/go-libp2p/core/crypto"

// BlockVerifiers is the list of verifiers/validators.
var BlockVerifiers = []Verifier{
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
}

// Verifier represents a block verifier/sealer
type Verifier struct {
	Address         string `json:"address"`
	InitialBalance  string `json:"initial_balance"`
	PublicKey       string `json:"public_key"`
	DataVerifier    bool   `json:"data_verifier"`
	PublicKeyCrypto crypto.PubKey
}

// IsValidVerifier verifies if an address is a validator
func IsValidVerifier(address string) bool {
	for _, v := range BlockVerifiers {
		if v.Address == address {
			return true
		}
	}
	return false
}
