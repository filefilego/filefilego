package keystore

import (
	"os"
	"testing"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/crypto"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		keysDir          string
		nodeIdentityData []byte
		expErr           string
	}{
		"keysDir empty": {
			expErr: "keysDir is empty",
		},
		"nodeIdentityData empty": {
			keysDir: "/tmp/filefilego/keystore",
			expErr:  "nodeIdentityData is empty",
		},
		"success": {
			keysDir:          "/tmp/filefilego/keystore",
			nodeIdentityData: []byte{1, 2, 3},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			keystore, err := New(tt.keysDir, tt.nodeIdentityData)
			if tt.expErr != "" {
				assert.Nil(t, keystore)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, keystore)
			}
		})
	}
}

func TestStore(t *testing.T) {
	keysDir := "/tmp/filefilego/keystore"
	nodeIdentityData, _ := crypto.RandomEntropy(30)
	keystore, err := New(keysDir, nodeIdentityData)
	assert.NoError(t, err)
	assert.NotNil(t, keystore)
	t.Cleanup(func() {
		os.RemoveAll(keysDir)
	})

	// invalid passphrase
	path, err := keystore.CreateKey("")
	assert.EqualError(t, err, "passphrase is empty")
	assert.Empty(t, path)

	// valid passphrase
	passphrase := "1234"
	path, err = keystore.CreateKey(passphrase)
	assert.NoError(t, err)
	assert.NotEmpty(t, path)
	assert.Equal(t, true, common.FileExists(path))

	jsonKey, err := os.ReadFile(path)
	assert.NoError(t, err)
	key, err := UnmarshalKey(jsonKey, passphrase)
	assert.NoError(t, err)

	// UnlockKey

	// wrong passphrase
	jwtToken, err := keystore.UnlockKey(key.Address, "23", false)
	assert.EqualError(t, err, "failed to unmarshal keystore file: mac mismatch")
	assert.Empty(t, jwtToken)

	// wrong address
	jwtToken, err = keystore.UnlockKey("0x1323", passphrase, false)
	assert.EqualError(t, err, "key not found on this node")
	assert.Empty(t, jwtToken)

	// valid
	jwtToken, err = keystore.UnlockKey(key.Address, passphrase, false)
	assert.NoError(t, err)
	assert.NotEmpty(t, jwtToken)

	unlockedKey, ok := keystore.unlockedKeys[key.Address]
	assert.True(t, ok)
	assert.Equal(t, jwtToken, unlockedKey.JWT)
	assert.Equal(t, key, unlockedKey.Key)

	// list keys in the keys directory
	keys, err := keystore.ListKeys()
	assert.NoError(t, err)
	assert.Contains(t, keys, key.Address+".json")

	// check if jwt is authorized

	// invalid jwt
	authorized, _, err := keystore.Authorized("wrong val")
	assert.False(t, authorized)
	assert.EqualError(t, err, "token is malformed: token contains an invalid number of segments")

	// valid jwt, wrong key
	authorized, _, err = keystore.Authorized(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`)
	assert.False(t, authorized)
	assert.EqualError(t, err, "token signature is invalid: signature is invalid")

	// valid token
	authorized, unlockedKeyFromAuth, err := keystore.Authorized(jwtToken)
	assert.True(t, authorized)
	assert.NoError(t, err)
	assert.Equal(t, unlockedKeyFromAuth, unlockedKey)

	// lockKey
	// wrong address
	locked, err := keystore.LockKey("wrongaddr", jwtToken)
	assert.False(t, locked)
	assert.EqualError(t, err, "address wrongaddr not found")

	// valid address and token
	locked, err = keystore.LockKey(key.Address, jwtToken)
	assert.True(t, locked)
	assert.NoError(t, err)

	// the token should not be authorized now
	authorized, _, err = keystore.Authorized(jwtToken)
	assert.False(t, authorized)
	assert.EqualError(t, err, "address is not unlocked")
}
