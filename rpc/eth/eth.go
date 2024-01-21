package eth

import (
	"net/http"
)

type EmptyArgs struct{}

// API represents eth service
type API struct{}

// ChainIDResponse is a key unlock response.
type ChainIDResponse string

// NewAPI creates a new address API to be served using JSONRPC.
func NewAPI() (*API, error) {
	return &API{}, nil
}

// ChainID returns chain id.
func (api *API) ChainID(_ *http.Request, _ *EmptyArgs, response *ChainIDResponse) error {
	*response = "0x1"
	return nil
}
