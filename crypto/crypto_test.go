package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/stretchr/testify/assert"
)

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	assert.NoError(t, err)
	assert.NotNil(t, keyPair)
}

func TestRestorePrivateKey(t *testing.T) {
	keyPair, _ := GenerateKeyPair()
	privateKeyBytes, err := keyPair.PrivateKey.Raw()
	assert.NoError(t, err)
	privKey, err := RestorePrivateKey(privateKeyBytes)
	assert.NoError(t, err)
	assert.Equal(t, keyPair.PrivateKey, privKey)
}

func TestPublicKeyToAndFromHex(t *testing.T) {
	keyPair, _ := GenerateKeyPair()
	pubKeyString, err := PublicKeyToHex(keyPair.PublicKey)
	assert.NoError(t, err)
	pubKey, err := PublicKeyFromHex(pubKeyString)
	assert.NoError(t, err)
	assert.Equal(t, keyPair.PublicKey, pubKey)

	// invalid hex public key
	_, err = PublicKeyFromHex("1243")
	assert.EqualError(t, err, "failed to decode: hex prefix is missing")

	// malformed
	_, err = PublicKeyFromHex("0x1243")
	assert.EqualError(t, err, "malformed public key: invalid length: 2")
}

func TestPrivateKeyToHex(t *testing.T) {
	keyPair, _ := GenerateKeyPair()
	privateKeyString, err := PrivateKeyToHex(keyPair.PrivateKey)
	assert.NoError(t, err)
	assert.NotEqual(t, "", privateKeyString)
	privKeyBytes, err := hexutil.Decode(privateKeyString)
	assert.NoError(t, err)
	priv, err := RestorePrivateKey(privKeyBytes)
	assert.NoError(t, err)
	assert.Equal(t, keyPair.PrivateKey, priv)
}

func TestPublicKeyFromBytes(t *testing.T) {
	keyPair, err := GenerateKeyPair()
	assert.NoError(t, err)
	pubKeyData, err := keyPair.PublicKey.Raw()
	assert.NoError(t, err)
	derivedPubKey, err := PublicKeyFromBytes(pubKeyData)
	assert.NoError(t, err)
	assert.Equal(t, keyPair.PublicKey, derivedPubKey)
}

func TestKeccak256(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		data   []byte
		hexVal string
		expErr string
	}{
		"empty bytes": {
			data:   []byte{}, // empty
			hexVal: "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		"1 byte": {
			data:   []byte{72, 101, 108, 108, 111}, // Hello
			hexVal: "06b3dfaec148fb1bb2b066f10ec285e7c9bf402ab32aa78a5d38e34566810cd2",
		},
		"2 byte": {
			data:   []byte{65}, // A
			hexVal: "03783fac2efed8fbc9ad443e592ee30e61d65f471140c10ca155e937b435b760",
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dt, err := Keccak256(tt.data)
			if tt.expErr != "" {
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.Equal(t, tt.hexVal, hexutil.EncodeNoPrefix(dt))
				assert.Len(t, dt, 32)
				assert.NotNil(t, dt)
			}
		})
	}
}

func TestRandomEntropy(t *testing.T) {
	data, err := RandomEntropy(0)
	assert.NoError(t, err)
	assert.Empty(t, data)

	data, err = RandomEntropy(10)
	assert.NoError(t, err)
	assert.Len(t, data, 10)
}

func TestRawPublicToAddress(t *testing.T) {
	pubAddr := "0x03fab2023a5b2acb8855085004dc173f67d66df5591afdc3fbc3435880b9c6338b"
	addr := "0xdd9a374e8dce9d656073ec153580301b7d2c3850"
	data, err := hexutil.Decode(pubAddr)
	assert.NoError(t, err)
	str, err := RawPublicToAddress(data)
	assert.NoError(t, err)
	assert.Equal(t, addr, str)
}

func TestRawPublicToAddressBytes(t *testing.T) {
	pubAddr := "0x03fab2023a5b2acb8855085004dc173f67d66df5591afdc3fbc3435880b9c6338b"
	addr := "0xdd9a374e8dce9d656073ec153580301b7d2c3850"
	addrBytes, err := hexutil.Decode(addr)
	assert.NoError(t, err)
	data, err := hexutil.Decode(pubAddr)
	assert.NoError(t, err)
	str, err := RawPublicToAddressBytes(data)
	assert.NoError(t, err)
	assert.EqualValues(t, addrBytes, str)
}

func TestSha1File(t *testing.T) {
	fileToBeCreated := "231283918239182931823.txt"
	t.Cleanup(func() {
		os.RemoveAll(fileToBeCreated)
	})
	filePath, err := writeToFile([]byte("hello"), fileToBeCreated)
	assert.NoError(t, err)
	hash, err := Sha1File(filePath)
	assert.NoError(t, err)
	assert.Equal(t, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", hash)
}

func writeToFile(data []byte, filePath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return "", fmt.Errorf("failed to open path: %w", err)
	}
	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to create path: %w", err)
	}
	defer file.Close()
	_, err = file.Write(data)
	if err != nil {
		return "", fmt.Errorf("failed to write data to path: %w", err)
	}
	return filePath, nil
}
