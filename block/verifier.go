package block

import (
	"sync"

	ffgcrypto "github.com/filefilego/filefilego/crypto"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

var mu sync.RWMutex

var blockVerifiers = []Verifier{
	{
		Address:      "0xdd9a374e8dce9d656073ec153580301b7d2c3850",
		PublicKey:    "0x03fab2023a5b2acb8855085004dc173f67d66df5591afdc3fbc3435880b9c6338b",
		DataVerifier: true,
	},
	{
		Address:      "0xe113a8e7de54c3edd455e0d597830b0aa9a838b2",
		PublicKey:    "0x03d8eddcba2ee1ce69aedf8f48d2a54c8421ed1289d6c91f014189e9423fc15720",
		DataVerifier: true,
	},
	{
		Address:      "0x0b9f90d53c678aff32e7abe5698a0ed8ffc49114",
		PublicKey:    "0x02ffea9f52bd9669c56e3ca112a66ef6e5b6c37b77fe472d46c9228232f7cb6c32",
		DataVerifier: true,
	},
	{
		Address:      "0x5823bfabf7993eeb265c69dc4de1068847342d61",
		PublicKey:    "0x03fdf7e5ea9ccdb6520cfd6fbdfecadabae08c302bbc38aae21dbc3f44892a0ac3",
		DataVerifier: true,
	},
	{
		Address:      "0xe3d6ad252cad7aef16a36df66040dffd58628d65",
		PublicKey:    "0x025085082ae6c0b6b4485981f715d21fd090a02019b85cb51ed71157e0720abc69",
		DataVerifier: true,
	},
	{
		Address:      "0x8a02c75f38685f31b413c5e464f6b5f21daea846",
		PublicKey:    "0x02b9cf282aac481709e9447e9c50fa8763ef8a03af39a2dee76260a841960ab5fe",
		DataVerifier: true,
	},
	{
		Address:      "0x740f7bc849d0538afcf899a9bd3146180ac94354",
		PublicKey:    "0x03d158f4350a8c4bcc421db3f490a0861ef52c041dc1e29fef9d16e8771e11d944",
		DataVerifier: true,
	},
	{
		Address:      "0xd2da7ec323f9ab02a0404a0d9f692a533584183c",
		PublicKey:    "0x022acb5676bde2090c303d099fe94199bf8b44dc01e9ef78d7c54d35f0d5271e63",
		DataVerifier: true,
	},
	{
		Address:      "0x97140774b67c96e49fe3d1ca3d0b5fcbd19dc26e",
		PublicKey:    "0x02c9ddefecb1e9b14228f7cb523a00ea49da9edcac428fcffa06d68a6e84d68ad5",
		DataVerifier: true,
	},
	{
		Address:      "0xfee2010d5cc6805db962a0f266ca7781f0b4dfc0",
		PublicKey:    "0x03cd040e15bdb0d715f2c08159e8eb33dc56fa8edddf1d64f0e87b0eea13aecea9",
		DataVerifier: true,
	},
	{
		Address:      "0x132a8a9c46d2781d8d9b0aa42ba3dc6a08f6d272",
		PublicKey:    "0x0236f569c974ceb39d25888603b1bfa587b0e0f4fb43381627e2cc48f3d028b7b7",
		DataVerifier: true,
	},
	{
		Address:      "0xbdf1465037356bac0e1133a422a769637738aff4",
		PublicKey:    "0x03ab0d35bd32cbb55d04d840d527687345b3c0d280784ccdc00bbc65da96acad36",
		DataVerifier: true,
	},
	{
		Address:      "0xa0b583056366b10510e344e147b3bf5008e2e8ca",
		PublicKey:    "0x02e27f73d94bf6d36a30cc301cf73472b7b93501dafdc0cfcc76a908118b6942e5",
		DataVerifier: true,
	},
	{
		Address:      "0xdab5f6da879f9613620eb7442df3e1910615cabb",
		PublicKey:    "0x033e09e62f82670ab8033e07f0a5970cd926b1b76979d485b0b4192565284b8c0f",
		DataVerifier: true,
	},
	{
		Address:      "0xa7f656a570ddbeb4d0b894334980b955baaef62e",
		PublicKey:    "0x0307ece2997860b5583191d2be60461caea0569712677947150969bd5a2ee0f230",
		DataVerifier: true,
	},
	{
		Address:      "0x3dee7773f4626ab90cca08e7ab2559afd7bfdfb1",
		PublicKey:    "0x03e0bc3e5dbc408636699ce6de850d2bd48a6b8e83ca6f86474436971ad53055f3",
		DataVerifier: true,
	},
}

// GetBlockVerifiers returns a list of verifiers.
func GetBlockVerifiers() []Verifier {
	mu.RLock()
	defer mu.RUnlock()

	return blockVerifiers
}

func GetBlockVerifiersPeerIDs() []peer.ID {
	mu.RLock()
	defer mu.RUnlock()

	peerIDs := make([]peer.ID, 0)
	for _, v := range blockVerifiers {
		peerID, err := v.PeerID()
		if err != nil {
			continue
		}
		peerIDs = append(peerIDs, peerID)
	}
	return peerIDs
}

// SetBlockVerifiers adds a verifier to the block verifiers.
func SetBlockVerifiers(v Verifier) {
	mu.Lock()
	defer mu.Unlock()

	blockVerifiers = append(blockVerifiers, v)
}

// Verifier represents a block verifier/sealer
type Verifier struct {
	Address         string `json:"address"`
	PublicKey       string `json:"public_key"`
	DataVerifier    bool   `json:"data_verifier"`
	PublicKeyCrypto crypto.PubKey
}

// PeerID get peer id from block verifier.
func (v *Verifier) PeerID() (peer.ID, error) {
	publicKey, err := ffgcrypto.PublicKeyFromHex(v.PublicKey)
	if err != nil {
		return "", err
	}
	return peer.IDFromPublicKey(publicKey)
}

// IsValidVerifier verifies if an address is a validator
func IsValidVerifier(address string) bool {
	mu.RLock()
	defer mu.RUnlock()
	for _, v := range blockVerifiers {
		if v.Address == address {
			return true
		}
	}
	return false
}
