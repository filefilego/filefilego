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

// UnlockAddressArgs arguments required for unlocking a key.
type UnlockAddressArgs struct {
	Address    string `json:"address"`
	Passphrase string `json:"passphrase"`
}

// UnlockAddressResponse is a key unlock response.
type UnlockAddressResponse struct {
	Token string `json:"token"`
}

// LockAddressArgs arguments required for locking a key.
type LockAddressArgs struct {
	Address string `json:"address"`
	Token   string `json:"token"`
}

// LockAddressResponse is a key unlock response.
type LockAddressResponse struct {
	Success bool `json:"success"`
}

// AuthorizedArgs arguments required for checking authorized token.
type AuthorizedArgs struct {
	Token string `json:"token"`
}

// AuthorizedResponse is a result of the authorization request.
type AuthorizedResponse struct {
	Authorized bool `json:"authorized"`
}

// BalanceOfAddressArgs arguments required for balance of an address.
type BalanceOfAddressArgs struct {
	Address string `json:"address"`
}

// BalanceOfAddressResponse represents the balance response of an address.
type BalanceOfAddressResponse struct {
	Balance    string `json:"balance"`
	BalanceHex string `json:"balance_hex"`
	Nounce     string `json:"nounce"`
	NextNounce string `json:"next_nounce"`
}

// AddressAPI represents address service
type AddressAPI struct {
	keystore   keystore.KeyLockUnlockLister
	blockchain blockchain.Interface
}

// ListAddressesResponse is a key unlock response.
type ListAddressesResponse struct {
	Addresses []string `json:"addresses"`
}

// NewAddressAPI creates a new address API to be served using JSONRPC.
func NewAddressAPI(keystore keystore.KeyLockUnlockLister, bchain blockchain.Interface) (*AddressAPI, error) {
	if keystore == nil {
		return nil, errors.New("keystore is nil")
	}

	if bchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	return &AddressAPI{
		keystore:   keystore,
		blockchain: bchain,
	}, nil
}

// List the addresses of the node.
func (api *AddressAPI) List(r *http.Request, args *EmptyArgs, response *ListAddressesResponse) error {
	addresses, err := api.keystore.ListKeys()
	if err != nil {
		return err
	}
	response.Addresses = make([]string, len(addresses))
	copy(response.Addresses, addresses)
	return nil
}

// Unlock a key given an address and a passphrase.
func (api *AddressAPI) Unlock(r *http.Request, args *UnlockAddressArgs, response *UnlockAddressResponse) error {
	jwtToken, err := api.keystore.UnlockKey(args.Address, args.Passphrase)
	if err != nil {
		return err
	}
	response.Token = jwtToken
	return nil
}

// Lock a key given an access token and the address.
func (api *AddressAPI) Lock(r *http.Request, args *LockAddressArgs, response *LockAddressResponse) error {
	locked, err := api.keystore.LockKey(args.Address, args.Token)
	if err != nil {
		return err
	}
	response.Success = locked
	return nil
}

// Authorized checks if an access token is currently available.
func (api *AddressAPI) Authorized(r *http.Request, args *AuthorizedArgs, response *AuthorizedResponse) error {
	ok, _, err := api.keystore.Authorized(args.Token)
	if err != nil {
		response.Authorized = false
		return nil
	}
	response.Authorized = ok
	return nil
}

// Balance of an address.
func (api *AddressAPI) Balance(r *http.Request, args *BalanceOfAddressArgs, response *BalanceOfAddressResponse) error {
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
