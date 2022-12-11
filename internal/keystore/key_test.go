package keystore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewKey(t *testing.T) {
	key, err := NewKey()
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.NotEmpty(t, key.ID)
}

func TestKeyMarshalUnmarshal(t *testing.T) {
	key, err := NewKey()
	assert.NoError(t, err)

	// empty passphrase
	data, err := key.MarshalToJSON("")
	assert.EqualError(t, err, "passphrase is empty")
	assert.Nil(t, data)

	// valid passphrase
	data, err = key.MarshalToJSON("1234")
	assert.NoError(t, err)
	assert.NotNil(t, key)

	// derive key with wrong passphrase
	derivedKey, err := UnmarshalKey(data, "222")
	assert.EqualError(t, err, "mac mismatch")
	assert.Nil(t, derivedKey)

	derivedKey, err = UnmarshalKey(data, "1234")
	assert.NoError(t, err)
	assert.Equal(t, key, derivedKey)
}

func TestUnmarshalKey(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		keyData    string
		passphrase string
		expErr     string
	}{
		"empty passphrase": {
			expErr: "passphrase is empty",
		},
		"empty key": {
			passphrase: "123",
			expErr:     "failed to unmarshal key data: unexpected end of JSON input",
		},
		"invalid version": {
			passphrase: "123",
			keyData:    `{}`,
			expErr:     "version mismatch",
		},
		"invalid cipher": {
			passphrase: "123",
			keyData:    `{"version": 3}`,
			expErr:     "cipher mismatch",
		},
		"invalid mac": {
			passphrase: "123",
			keyData:    `{"version": 3, "crypto":{"cipher":"aes-128-ctr", "mac": "0"}}`,
			expErr:     "failed to decode mac: encoding/hex: odd length hex string",
		},
		"invalid cipherParams": {
			passphrase: "123",
			keyData:    `{"version": 3, "crypto":{"cipher":"aes-128-ctr", "mac": "1232", "cipherparams":{ "iv":"0" }}}`,
			expErr:     "failed to decode cipher params iv: encoding/hex: odd length hex string",
		},
		"invalid salt": {
			passphrase: "123",
			keyData:    `{"version": 3, "crypto":{"cipher":"aes-128-ctr", "mac": "1232", "kdfparams": {"salt": "0"}, "cipherparams":{ "iv":"1232" }}}`,
			expErr:     "failed to decode salt: encoding/hex: odd length hex string",
		},
		"invalid cipherText": {
			passphrase: "123",
			keyData:    `{"version": 3, "crypto":{"cipher":"aes-128-ctr", "mac": "1232", "ciphertext": "0", "kdfparams": {"salt": "1232"}, "cipherparams":{ "iv":"1232" }}}`,
			expErr:     "failed to decode cipher text: encoding/hex: odd length hex string",
		},
		"failed to derive key": {
			passphrase: "123",
			keyData:    `{"version": 3, "crypto":{"cipher":"aes-128-ctr", "mac": "1232", "ciphertext": "1232", "kdfparams": {"salt": "1232"}, "cipherparams":{ "iv":"1232" }}}`,
			expErr:     "failed to derive key: scrypt: N must be > 1 and a power of 2",
		},
		"mac mismatch": {
			passphrase: "1234",
			keyData:    `{ "address": "0x6e5755884220bf9d3d30eb1b0853cd8d8db0dc86", "crypto": { "cipher": "aes-128-ctr", "ciphertext": "", "cipherparams": { "iv": "2e250214b665831ad7a5ed84508445e2" }, "kdf": "scrypt", "kdfparams": { "n": 262144, "r": 8, "p": 1, "dklen": 32, "salt": "cf2a22196d7865aaa23fea7d6eea03a93270edf23bebe8c9297d0b20db82d39d" }, "mac": "ba035e813a993cfdcf621915b6b55e5470bbfb67e0ecaa30d286cd6e7fe34b69" }, "id": "252841d8-393e-42ea-a793-9f9860cb32d3", "version": 3 }`,
			expErr:     "mac mismatch",
		},
		"invalid uuid": {
			passphrase: "1234",
			keyData:    `{ "address": "0x6e5755884220bf9d3d30eb1b0853cd8d8db0dc86", "crypto": { "cipher": "aes-128-ctr", "ciphertext": "de97f2cd68a444158624340adfdf6f5ac8703f72998a1a3b5c15dc6baf506ff0", "cipherparams": { "iv": "2e250214b665831ad7a5ed84508445e2" }, "kdf": "scrypt", "kdfparams": { "n": 262144, "r": 8, "p": 1, "dklen": 32, "salt": "cf2a22196d7865aaa23fea7d6eea03a93270edf23bebe8c9297d0b20db82d39d" }, "mac": "ba035e813a993cfdcf621915b6b55e5470bbfb67e0ecaa30d286cd6e7fe34b69" }, "id": "252841d8-390cb32d3", "version": 3 }`,
			expErr:     "failed to parse the uuid from encrypted json file: invalid UUID length: 18",
		},
		"success": {
			passphrase: "1234",
			keyData:    `{ "address": "0x6e5755884220bf9d3d30eb1b0853cd8d8db0dc86", "crypto": { "cipher": "aes-128-ctr", "ciphertext": "de97f2cd68a444158624340adfdf6f5ac8703f72998a1a3b5c15dc6baf506ff0", "cipherparams": { "iv": "2e250214b665831ad7a5ed84508445e2" }, "kdf": "scrypt", "kdfparams": { "n": 262144, "r": 8, "p": 1, "dklen": 32, "salt": "cf2a22196d7865aaa23fea7d6eea03a93270edf23bebe8c9297d0b20db82d39d" }, "mac": "ba035e813a993cfdcf621915b6b55e5470bbfb67e0ecaa30d286cd6e7fe34b69" }, "id": "252841d8-393e-42ea-a793-9f9860cb32d3", "version": 3 }`,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			key, err := UnmarshalKey([]byte(tt.keyData), tt.passphrase)
			if tt.expErr != "" {
				assert.Nil(t, key)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, key)
			}
		})
	}
}

func TestGenerateFilename(t *testing.T) {
	filename := generateFilename("0x123")
	assert.Contains(t, filename, "0x123")
}
