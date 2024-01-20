package eth

import (
	"net/http"
)

type EmptyArgs struct{}

// EthAPI represents eth service
type EthAPI struct{}

// ChainIDResponse is a key unlock response.
type ChainIDResponse string

// NewAddressAPI creates a new address API to be served using JSONRPC.
func NewEthAPI() (*EthAPI, error) {
	return &EthAPI{}, nil
}

// ChainId returns chain id.
func (api *EthAPI) ChainId(_ *http.Request, _ *EmptyArgs, response *ChainIDResponse) error {
	*response = "0x1"
	return nil
}
