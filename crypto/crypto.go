package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	// nolint:gosec
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cespare/xxhash"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/libp2p/go-libp2p/core/crypto"
	"golang.org/x/crypto/sha3"
)

// AddressLength represents the length of an address.
const AddressLength = 20

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

// PrivateKeyToEthPrivate returns an eth private key.
func PrivateKeyToEthPrivate(privateKey []byte) (*ecdsa.PrivateKey, error) {
	ethPriv, err := ethcrypto.ToECDSA(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key to eth private: %w", err)
	}

	return ethPriv, nil
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

// RawCompressedPublicToEthAddress returns the address of the public key in eth compatible.
func RawCompressedPublicToEthAddress(data []byte) (string, error) {
	pubKey, err := secp256k1.ParsePubKey(data)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	uncompressedPubKey := pubKey.SerializeUncompressed()
	addressBytes, err := RawPublicToAddressBytes(uncompressedPubKey[1:])
	if err != nil {
		return "", fmt.Errorf("failed to get address bytes: %w", err)
	}

	var cbuf [AddressLength*2 + 2]byte
	copy(cbuf[:2], "0x")
	hex.Encode(cbuf[2:], addressBytes)
	buf := cbuf[:]

	sha := sha3.NewLegacyKeccak256()
	sha.Write(buf[2:])
	hash := sha.Sum(nil)
	for i := 2; i < len(buf); i++ {
		hashByte := hash[(i-2)/2]
		if i%2 == 0 {
			hashByte >>= 4
		} else {
			hashByte &= 0xf
		}
		if buf[i] > '9' && hashByte > 7 {
			buf[i] -= 32
		}
	}

	return string(buf), nil
}

// Sha1File performs a sha1 hash on a file
func Sha1File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// nolint:gosec
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to copy file content to sha1 handler: %w", err)
	}

	return hexutil.EncodeNoPrefix(h.Sum(nil)), nil
}

// XXHashFile peforms a xxhash hash on a file.
func XXHashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// nolint:gosec
	h := xxhash.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to copy file content to xxhash handler: %w", err)
	}

	return hexutil.EncodeNoPrefix(h.Sum(nil)), nil
}

// Sha256 performs a sha256 hash of input.
func Sha256(data []byte) []byte {
	hash := sha256.Sum256(data)
	bts := hash[:]
	return bts
}
