package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/libp2p/go-libp2p/core/crypto"
	"golang.org/x/crypto/sha3"
)

// KeyPair represents a private, publick key and the address.
type KeyPair struct {
	PrivateKey crypto.PrivKey
	PublicKey  crypto.PubKey
	Address    string
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

	publicKeyHex, err := RawPublicToAddress(publicBytes)
	if err != nil {
		return KeyPair{}, err
	}

	return KeyPair{PrivateKey: priv, PublicKey: pub, Address: publicKeyHex}, nil
}

// RestorePrivateKey unmarshals the privateKey
func RestorePrivateKey(privateKey []byte) (crypto.PrivKey, error) {
	return crypto.UnmarshalSecp256k1PrivateKey(privateKey)
}

// PublicKeyToHex returns the hex value of a pubkey.
func PublicKeyToHex(k crypto.PubKey) (string, error) {
	bts, err := k.Raw()
	return hexutil.Encode(bts), err
}

// PrivateKeyToHex returns the hex value of a PrivKey.
func PrivateKeyToHex(k crypto.PrivKey) (string, error) {
	bts, err := k.Raw()
	return hexutil.Encode(bts), err
}

// PublicKeyFromHex returns a public key from hex.
func PublicKeyFromHex(str string) (crypto.PubKey, error) {
	bts, err := hexutil.Decode(str)
	if err != nil {
		return nil, fmt.Errorf("failed to decode: %w", err)
	}
	return crypto.UnmarshalSecp256k1PublicKey(bts)
}

// PublicKeyFromBytes returns a public key from bytes.
func PublicKeyFromBytes(data []byte) (crypto.PubKey, error) {
	return crypto.UnmarshalSecp256k1PublicKey(data)
}

// Keccak256 return sha3 of a given byte array
func Keccak256(data ...[]byte) ([]byte, error) {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		_, err := d.Write(b)
		if err != nil {
			return nil, err
		}
	}
	return d.Sum(nil), nil
}

// RandomEntropy bytes from rand.Reader
func RandomEntropy(length int) ([]byte, error) {
	buf := make([]byte, length)
	n, err := io.ReadFull(rand.Reader, buf)
	if err != nil || n != length {
		return nil, errors.New("failed to read random bytes")
	}
	return buf, nil
}

// RawPublicToAddress returns the address of the public key.
func RawPublicToAddress(data []byte) (string, error) {
	keccacBytes, err := Keccak256(data)
	if err != nil {
		return "", err
	}
	return hexutil.Encode(keccacBytes[12:]), nil
}

// RawPublicToAddressBytes returns the address of the public key in byte array.
func RawPublicToAddressBytes(data []byte) ([]byte, error) {
	keccacBytes, err := Keccak256(data)
	if err != nil {
		return nil, err
	}
	return keccacBytes[12:], nil
}
