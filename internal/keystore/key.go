package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/filefilego/filefilego/internal/crypto"
	"github.com/google/uuid"
	"golang.org/x/crypto/scrypt"
)

var (
	nameKDF      = "scrypt"
	scryptKeyLen = 32
	scryptN      = 1 << 18
	scryptR      = 8
	scryptP      = 1
	ksVersion    = 3
	ksCipher     = "aes-128-ctr"
)

// Key represents a keypair to be stored.
type Key struct {
	*crypto.KeyPair
	ID uuid.UUID
}

// NewKey new Key
func NewKey() (*Key, error) {
	keypair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random uuid: %w", err)
	}

	return &Key{
		ID:      id,
		KeyPair: &keypair,
	}, nil
}

// MarshalToJSON marshals a key to json byte array.
func (key *Key) MarshalToJSON(passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase is empty")
	}
	salt, err := crypto.RandomEntropy(32)
	if err != nil {
		return nil, err
	}
	dk, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	iv, err := crypto.RandomEntropy(aes.BlockSize)
	if err != nil {
		return nil, err
	}
	enckey := dk[:16]

	privateKeyBytes, err := key.KeyPair.PrivateKey.Raw()
	if err != nil {
		return nil, err
	}
	aesBlock, err := aes.NewCipher(enckey)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	cipherText := make([]byte, len(privateKeyBytes))
	stream.XORKeyStream(cipherText, privateKeyBytes)

	mac, err := crypto.Keccak256(dk[16:32], cipherText)
	if err != nil {
		return nil, err
	}
	cipherParamsJSON := cipherparamsJSON{
		IV: hex.EncodeToString(iv),
	}

	sp := ScryptParams{
		N:          scryptN,
		R:          scryptR,
		P:          scryptP,
		DKeyLength: scryptKeyLen,
		Salt:       hex.EncodeToString(salt),
	}

	keyjson := cryptoJSON{
		Cipher:       ksCipher,
		CipherText:   hex.EncodeToString(cipherText),
		CipherParams: cipherParamsJSON,
		KDF:          nameKDF,
		KDFParams:    sp,
		MAC:          hex.EncodeToString(mac),
	}

	encjson := encryptedKeyJSON{
		Address: key.KeyPair.Address,
		Crypto:  keyjson,
		ID:      key.ID.String(),
		Version: ksVersion,
	}
	data, err := json.MarshalIndent(&encjson, "", "  ")
	if err != nil {
		return nil, err
	}
	return data, nil
}

// UnmarshalKey decrypts the private key
func UnmarshalKey(data []byte, passphrase string) (*Key, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase is empty")
	}
	encjson := encryptedKeyJSON{}
	if err := json.Unmarshal(data, &encjson); err != nil {
		return nil, fmt.Errorf("failed to unmarshal key data: %w", err)
	}
	if encjson.Version != ksVersion {
		return nil, errors.New("version mismatch")
	}
	if encjson.Crypto.Cipher != ksCipher {
		return nil, errors.New("cipher mismatch")
	}
	mac, err := hex.DecodeString(encjson.Crypto.MAC)
	if err != nil {
		return nil, fmt.Errorf("failed to decode mac: %w", err)
	}
	iv, err := hex.DecodeString(encjson.Crypto.CipherParams.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cipher params iv: %w", err)
	}
	salt, err := hex.DecodeString(encjson.Crypto.KDFParams.Salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}
	ciphertext, err := hex.DecodeString(encjson.Crypto.CipherText)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cipher text: %w", err)
	}
	dk, err := scrypt.Key([]byte(passphrase), salt, encjson.Crypto.KDFParams.N, encjson.Crypto.KDFParams.R, encjson.Crypto.KDFParams.P, encjson.Crypto.KDFParams.DKeyLength)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	hash, err := crypto.Keccak256(dk[16:32], ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to hash key and ciphertext: %w", err)
	}
	if !bytes.Equal(hash, mac) {
		return nil, errors.New("mac mismatch")
	}
	aesBlock, err := aes.NewCipher(dk[:16])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outputkey := make([]byte, len(ciphertext))
	stream.XORKeyStream(outputkey, ciphertext)
	privKey, err := crypto.RestorePrivateKey(outputkey)
	if err != nil {
		return nil, fmt.Errorf("failed to restore private key: %w", err)
	}

	derivedID, err := uuid.Parse(encjson.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the uuid from encrypted json file: %w", err)
	}

	return &Key{
		ID: derivedID,
		KeyPair: &crypto.KeyPair{
			PrivateKey: privKey,
			PublicKey:  privKey.GetPublic(),
			Address:    encjson.Address,
		},
	}, nil
}

func generateFilename(address string) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s.json", toISO8601(ts), address)
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}
