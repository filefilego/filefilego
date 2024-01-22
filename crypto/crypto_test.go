package crypto

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/stretchr/testify/assert"
)

var (
	testmsg, _     = hexutil.Decode("0xce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008")
	testsig, _     = hexutil.Decode("0x90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc9301")
	testpubkey, _  = hexutil.Decode("0x04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652")
	testpubkeyc, _ = hexutil.Decode("0x02e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a")
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

func TestPrivateKeyToEthPrivate(t *testing.T) {
	kp, err := GenerateKeyPair()
	assert.NoError(t, err)
	pkBytes, err := kp.PrivateKey.Raw()
	assert.NoError(t, err)
	ethPriv, err := PrivateKeyToEthPrivate(pkBytes)
	assert.NoError(t, err)
	assert.NotNil(t, ethPriv)
	// get the underlying bytes and compare to the original
	ethPkBytes := ethcrypto.FromECDSA(ethPriv)
	assert.NotEmpty(t, ethPkBytes)
	assert.EqualValues(t, ethPkBytes, pkBytes)
}

func TestRawPublicToEthAddress(t *testing.T) {
	testAddrHex := "0x96233bcC823159C3c08EB76a24E98F20CE7d48DE"
	testPrivHex := "ef66677e9aef9396d991fa876c33265921a09a31c717d48636abd7f99a45d0b5"

	pkbytes, err := hexutil.DecodeNoPrefix(testPrivHex)
	assert.NoError(t, err)
	pkey, err := RestorePrivateKey(pkbytes)
	assert.NoError(t, err)

	rawBytes, err := pkey.GetPublic().Raw()
	assert.NoError(t, err)

	derivedEthAddr, err := RawCompressedPublicToEthAddress(rawBytes)
	assert.NoError(t, err)
	assert.Equal(t, testAddrHex, derivedEthAddr)
}

func TestVerifySignature(t *testing.T) {
	sig := testsig[:len(testsig)-1] // remove recovery id

	// public key compressed
	ok := ethcrypto.VerifySignature(testpubkeyc, testmsg, sig)
	assert.True(t, ok)

	// public key uncompressed
	ok = ethcrypto.VerifySignature(testpubkey, testmsg, sig)
	assert.True(t, ok)
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
