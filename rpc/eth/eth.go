package eth

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"

	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common/hexutil"
)

const (
	// 0.001 FFG
	gasPrice     = "0x1"
	estimatedGas = "0x38d7ea4c68000"
)

type bcInterface interface {
	GetHeight() uint64
	GetAddressState(address []byte) (blockchain.AddressState, error)
}

type EmptyArgs struct{}

// API represents eth service
type API struct {
	chainID string
	bc      bcInterface
}

// NewAPI creates a new address API to be served using JSONRPC.
func NewAPI(blockchain bcInterface, chainID string) (*API, error) {
	return &API{
		chainID: chainID,
		bc:      blockchain,
	}, nil
}

// SendRawTransaction sends a raw transaction.
func (api *API) SendRawTransaction(_ *http.Request, _ *GetCodeArgs, response *GetCodeResponse) error {
	// tx := new(types.Transaction)
	// 	if err := tx.UnmarshalBinary(input); err != nil {
	// 		return common.Hash{}, err
	// 	}
	// 	return SubmitTransaction(ctx, s.b, tx)

	*response = "0x"
	return nil
}

type GetCodeResponse string

type GetCodeArgs []interface{}

// GetCode returns 0x
func (api *API) GetCode(_ *http.Request, _ *GetCodeArgs, response *GetCodeResponse) error {
	*response = "0x"
	return nil
}

type GetTransactionCountResponse string

type GetTransactionCountArgs []interface{}

// GetTransactionCount returns the transaction counts of an address.
func (api *API) GetTransactionCount(_ *http.Request, args *GetTransactionCountArgs, response *GetTransactionCountResponse) error {
	arg1, ok := (*args)[0].(string)
	if !ok {
		return errors.New("invalid address")
	}

	addr, err := hexutil.Decode(arg1)
	if err != nil {
		return fmt.Errorf("failed to decode address: %w", err)
	}

	state, err := api.bc.GetAddressState(addr)
	if err != nil {
		*response = GetTransactionCountResponse("0x0")
		return nil
	}

	nounce, err := state.GetNounce()
	if err != nil {
		*response = GetTransactionCountResponse("0x0")
		return nil
	}

	*response = GetTransactionCountResponse(hexutil.EncodeUint64(nounce))
	return nil
}

// GasPriceResponse
type GasPriceResponse string

// GasPrice returns the gas price.
func (api *API) GasPrice(_ *http.Request, _ *EmptyArgs, response *GasPriceResponse) error {
	*response = GasPriceResponse(gasPrice)
	return nil
}

type EstimateGasResponse string

type EstimateGasArgs struct {
	Data     string `json:"data"`
	From     string `json:"from"`
	To       string `json:"to"`
	GasPrice string `json:"gasPrice"`
	Value    string `json:"value"`
}

// EstimateGas returns the estimated gas.
func (api *API) EstimateGas(_ *http.Request, args *EstimateGasArgs, response *EstimateGasResponse) error {
	*response = EstimateGasResponse(estimatedGas)
	return nil
}

// ChainIDResponse
type ChainIDResponse string

// ChainID returns chain id.
func (api *API) ChainID(_ *http.Request, _ *EmptyArgs, response *ChainIDResponse) error {
	*response = ChainIDResponse(api.chainID)
	return nil
}

// Version returns chain id in human readable format.
func (api *API) Version(_ *http.Request, _ *EmptyArgs, response *ChainIDResponse) error {
	chain, _ := hexutil.DecodeBig(api.chainID)
	*response = ChainIDResponse(fmt.Sprintf("%d", chain.Uint64()))
	return nil
}

// BlockNumberResponse is a key unlock response.
type BlockNumberResponse string

// BlockNumber returns the block height.
func (api *API) BlockNumber(_ *http.Request, _ *EmptyArgs, response *BlockNumberResponse) error {
	height := hexutil.EncodeUint64(api.bc.GetHeight())

	*response = BlockNumberResponse(height)
	return nil
}

type GetBalanceResponse string

type GetBalanceArgs []interface{}

// GetBalance returns the address balance.
func (api *API) GetBalance(_ *http.Request, args *GetBalanceArgs, response *GetBalanceResponse) error {
	arg1, ok := (*args)[0].(string)
	if !ok {
		return errors.New("invalid address")
	}

	addr, err := hexutil.Decode(arg1)
	if err != nil {
		return fmt.Errorf("failed to decode address: %w", err)
	}

	state, err := api.bc.GetAddressState(addr)
	if err != nil {
		*response = GetBalanceResponse("0x0")
		return nil
	}

	balance, err := state.GetBalance()
	if reflect.ValueOf(balance).IsNil() || balance == nil || err != nil {
		*response = GetBalanceResponse("0x0")
		return nil
	}

	balanceHex := hexutil.EncodeBig(balance)

	*response = GetBalanceResponse(balanceHex)
	return nil
}
