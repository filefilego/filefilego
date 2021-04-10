package crypto

import (
	"crypto/sha256"

	"github.com/filefilego/filefilego/common/hexutil"

	crypto "github.com/libp2p/go-libp2p-core/crypto"
	pb "github.com/libp2p/go-libp2p-core/crypto/pb"
	sha3 "golang.org/x/crypto/sha3"
)

// KeyPair
type KeyPair struct {
	Private crypto.PrivKey
	Address string
}

// GenerateKeyPair returns a new keypair
func GenerateKeyPair() (KeyPair, error) {
	priv, pub, err := crypto.GenerateKeyPair(crypto.Secp256k1, 256)
	if err != nil {
		return KeyPair{}, err
	}
	publicBytes, err := pub.Raw()
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Private: priv, Address: RawPublicToAddress(publicBytes)}, nil
}

// RestorePrivateKey unmarshals the privateKey
func RestorePrivateKey(privateKey []byte) (crypto.PrivKey, error) {
	return crypto.UnmarshalSecp256k1PrivateKey(privateKey)
}

// PublicKeyHex returns the hex value of a pubkey
func PublicKeyHex(k crypto.PubKey) (string, error) {
	bts, err := k.Raw()
	return hexutil.Encode(bts), err
}

// PublicKeyFromRawHex creates a protobuf envelope and inserts data from hex
func PublicKeyFromRawHex(str string) (pk crypto.PubKey, _ error) {

	bts, err := hexutil.Decode(str)
	if err != nil {
		return pk, err
	}

	// the protobug message and keytype
	ss := pb.PublicKey{
		Type: pb.KeyType_Secp256k1,
		Data: bts,
	}
	copy(ss.Data, bts)
	finalKey, err := crypto.PublicKeyFromProto(&ss)
	if err != nil {
		return pk, err
	}
	return finalKey, nil

}

// UnmarshalSecp256k1PubKey unmarshals a secp256k1 pubKey
func UnmarshalSecp256k1PubKey(pubKey []byte) (crypto.PubKey, error) {
	return crypto.UnmarshalSecp256k1PublicKey(pubKey)
}

// RestorePrivateToKeyPair unmarshals the privateKey and returns a the priv as well the pub keys
func RestorePrivateToKeyPair(privateKey []byte) (crypto.PrivKey, crypto.PubKey, error) {
	priv, err := RestorePrivateKey(privateKey)
	pub := priv.GetPublic()
	if err != nil {
		return priv, pub, err
	}
	return priv, pub, nil
}

// PublicToAddress returns the address of a public key
func RawPublicToAddress(data []byte) string {
	return hexutil.Encode(Keccak256(data)[12:])
}

//Keccak256 return sha3 of a given byte array
func Keccak256(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// Sha256HashHexBytes retuens the hex representation of data
func Sha256HashHexBytes(data []byte) []byte {
	hash := sha256.Sum256(data)
	bts := hash[:]
	return bts
}
