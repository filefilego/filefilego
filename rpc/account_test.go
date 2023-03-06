package rpc

import (
	"net/http"
	"os"
	"testing"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/database"
	"github.com/filefilego/filefilego/keystore"
	"github.com/filefilego/filefilego/search"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestNewAccountAPI(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		keystore   keystore.KeyLockUnlocker
		blockchain blockchain.Interface
		expErr     string
	}{
		"no keystore": {
			expErr: "keystore is nil",
		},
		"no blockchain": {
			keystore: &keystore.Store{},
			expErr:   "blockchain is nil",
		},
		"success": {
			keystore:   &keystore.Store{},
			blockchain: &blockchain.Blockchain{},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, err := NewAccountAPI(tt.keystore, tt.blockchain)
			if tt.expErr != "" {
				assert.Nil(t, api)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, api)
				assert.NoError(t, err)
			}
		})
	}
}

func TestAccountAPIMethods(t *testing.T) {
	randomData, err := ffgcrypto.RandomEntropy(40)
	assert.NoError(t, err)
	store, err := keystore.New("testksdir", randomData)
	assert.NoError(t, err)

	keypath, err := store.CreateKey("123")
	assert.NoError(t, err)
	assert.NotEqual(t, "", keypath)

	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)

	db, err := leveldb.OpenFile("acountapi.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("acountapi.db")
		os.RemoveAll("testksdir")
	})
	blockchain, err := blockchain.New(driver, &search.Search{}, genesisblockValid.Hash)
	assert.NoError(t, err)
	err = blockchain.InitOrLoad()
	assert.NoError(t, err)

	api, err := NewAccountAPI(store, blockchain)
	assert.NoError(t, err)
	assert.NotNil(t, api)

	keydata, err := os.ReadFile(keypath)
	assert.NoError(t, err)
	key, err := keystore.UnmarshalKey(keydata, "123")
	assert.NoError(t, err)

	unlockArg := &UnlockAccountArgs{Address: "wrong", Passphrase: "ddf"}
	unlockResp := &UnlockAccountResponse{}
	// Unlock
	// empty addr
	err = api.Unlock(&http.Request{}, unlockArg, unlockResp)
	assert.EqualError(t, err, "key not found on this node")
	unlockArg.Address = key.Address
	unlockArg.Passphrase = "123"
	err = api.Unlock(&http.Request{}, unlockArg, unlockResp)
	assert.NoError(t, err)
	assert.NotEmpty(t, unlockResp.Token)

	// Lock
	// empty args
	lockAccountArgs := &LockAccountArgs{}
	lockAccountResponse := &LockAccountResponse{}
	err = api.Lock(&http.Request{}, lockAccountArgs, lockAccountResponse)
	assert.EqualError(t, err, "address  not found")

	// valid
	lockAccountArgs.Address = key.Address
	lockAccountArgs.Token = unlockResp.Token
	err = api.Lock(&http.Request{}, lockAccountArgs, lockAccountResponse)
	assert.NoError(t, err)
	assert.True(t, lockAccountResponse.Success)

	// Balance
	balanceArgs := &BalanceOfAccountArgs{}
	balanceResponse := &BalanceOfAccountResponse{}
	err = api.Balance(&http.Request{}, balanceArgs, balanceResponse)
	assert.EqualError(t, err, "input is empty")

	// nonexisting addr
	balanceArgs.Address = "0x01"
	err = api.Balance(&http.Request{}, balanceArgs, balanceResponse)
	assert.NoError(t, err)
	assert.Equal(t, BalanceOfAccountResponse{Balance: "0", BalanceHex: "0x0", Nounce: "0x0", NextNounce: "0x1"}, *balanceResponse)

	// valid address of genesis validator
	balanceArgs = &BalanceOfAccountArgs{}
	balanceResponse = &BalanceOfAccountResponse{}
	balanceArgs.Address = genesisblockValid.Transactions[0].From
	err = api.Balance(&http.Request{}, balanceArgs, balanceResponse)
	assert.NoError(t, err)
	assert.Equal(t, BalanceOfAccountResponse{Balance: "40.000000000000000000", BalanceHex: "0x22b1c8c1227a00000", Nounce: "0x0", NextNounce: "0x1"}, *balanceResponse)
}
