package rpc

import (
	"errors"
	"net/http"

	"github.com/filefilego/filefilego/internal/keystore"
)

// UnlockAccountArgs arguments required for unlocking a key.
type UnlockAccountArgs struct {
	Address    string `json:"address"`
	Passphrase string `json:"passphrase"`
}

// UnlockAccountResponse is a key unlock response.
type UnlockAccountResponse struct {
	Token string `json:"token"`
}

// LockAccountArgs arguments required for locking a key.
type LockAccountArgs struct {
	Address string `json:"address"`
	Token   string `json:"token"`
}

// LockAccountResponse is a key unlock response.
type LockAccountResponse struct {
	Success bool `json:"success"`
}

// AccountAPI represents account service
type AccountAPI struct {
	keystore keystore.KeyLockUnlocker
}

// NewAccountAPI creates a new accounts API to be served using JSONRPC.
func NewAccountAPI(keystore keystore.KeyLockUnlocker) (*AccountAPI, error) {
	if keystore == nil {
		return nil, errors.New("keystore is nil")
	}

	return &AccountAPI{
		keystore: keystore,
	}, nil
}

// Unlock a key given an address and a passphrase.
func (api *AccountAPI) Unlock(r *http.Request, args *UnlockAccountArgs, response *UnlockAccountResponse) error {
	jwtToken, err := api.keystore.UnlockKey(args.Address, args.Passphrase)
	if err != nil {
		return err
	}
	response.Token = jwtToken
	return nil
}

// Lock a key given an access token and the address.
func (api *AccountAPI) Lock(r *http.Request, args *LockAccountArgs, response *LockAccountResponse) error {
	locked, err := api.keystore.LockKey(args.Address, args.Token)
	if err != nil {
		return err
	}
	response.Success = locked
	return nil
}
