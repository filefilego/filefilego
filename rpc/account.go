package rpc

import (
	"errors"
	"net/http"

	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/keystore"
)

const zeroHex = "0x0"

const oneHex = "0x1"

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

// BalanceOfAccountArgs arguments required for balance of an address.
type BalanceOfAccountArgs struct {
	Address string `json:"address"`
}

// BalanceOfAccountResponse represents the balance response of an address.
type BalanceOfAccountResponse struct {
	Balance    string `json:"balance"`
	BalanceHex string `json:"balance_hex"`
	Nounce     string `json:"nounce"`
	NextNounce string `json:"next_nounce"`
}

// AccountAPI represents account service
type AccountAPI struct {
	keystore   keystore.KeyLockUnlocker
	blockchain blockchain.Interface
}

// NewAccountAPI creates a new accounts API to be served using JSONRPC.
func NewAccountAPI(keystore keystore.KeyLockUnlocker, bchain blockchain.Interface) (*AccountAPI, error) {
	if keystore == nil {
		return nil, errors.New("keystore is nil")
	}

	if bchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	return &AccountAPI{
		keystore:   keystore,
		blockchain: bchain,
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

// Balance of an address.
func (api *AccountAPI) Balance(r *http.Request, args *BalanceOfAccountArgs, response *BalanceOfAccountResponse) error {
	addressBytes, err := hexutil.Decode(args.Address)
	if err != nil {
		return err
	}

	state, err := api.blockchain.GetAddressState(addressBytes)
	if err != nil {
		response.Balance = "0"
		response.BalanceHex = zeroHex
		response.Nounce = zeroHex
		response.NextNounce = oneHex
		return nil
	}

	balance, err := state.GetBalance()
	if err != nil {
		response.Balance = "0"
		response.BalanceHex = zeroHex
		response.Nounce = zeroHex
		response.NextNounce = oneHex
		return nil
	}

	nounce, err := state.GetNounce()
	if err != nil {
		response.Nounce = zeroHex
		response.NextNounce = oneHex
	}

	response.Balance = common.FormatBigWithSeperator(common.LeftPad2Len(balance.Text(10), "0", 19), ".", 18)
	response.BalanceHex = hexutil.EncodeBig(balance)
	response.Nounce = hexutil.EncodeUint64(nounce)
	response.NextNounce = hexutil.EncodeUint64(nounce + 1)

	return nil
}
