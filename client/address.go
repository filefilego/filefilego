package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/filefilego/filefilego/rpc"
)

// BalanceOfAddress represents the balance response of an address.
type BalanceOfAddress struct {
	Balance    string
	BalanceHex string
	Nounce     string
	NextNounce string
}

// ListAddresses lists the available addresses
func (cli *Client) ListAddresses(ctx context.Context) ([]string, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "address.List",
		Params:  []interface{}{rpc.EmptyArgs{}},
		ID:      1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return nil, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return nil, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	listAddresses := rpc.ListAddressesResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return nil, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &listAddresses); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return listAddresses.Addresses, nil
}

// UnlockAddress unlocks an address or a node identity key.
func (cli *Client) UnlockAddress(ctx context.Context, address, passphrase string) (string, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "address.Unlock",
		Params: []interface{}{rpc.UnlockAddressArgs{
			Address:    address,
			Passphrase: passphrase,
		}},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return "", fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return "", errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return "", errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	unlockedAddress := rpc.UnlockAddressResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return "", errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &unlockedAddress); err != nil {
		return "", fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return unlockedAddress.Token, nil
}

// LockAddress removes the unlocked address and jwt token to forbid access.
func (cli *Client) LockAddress(ctx context.Context, address, token string) (bool, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "address.Lock",
		Params: []interface{}{rpc.LockAddressArgs{
			Address: address,
			Token:   token,
		}},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return false, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return false, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return false, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return false, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return false, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	lockedAddress := rpc.LockAddressResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return false, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &lockedAddress); err != nil {
		return false, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return lockedAddress.Success, nil
}

// Authorized checks if an access token is authorized.
func (cli *Client) Authorized(ctx context.Context, token string) (bool, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "address.Lock",
		Params: []interface{}{rpc.AuthorizedArgs{
			Token: token,
		}},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return false, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return false, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return false, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return false, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return false, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	authorizedResponse := rpc.AuthorizedResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return false, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &authorizedResponse); err != nil {
		return false, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return authorizedResponse.Authorized, nil
}

// Balance returns the balance and nounces of an address.
func (cli *Client) Balance(ctx context.Context, address string) (BalanceOfAddress, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "address.Balance",
		Params: []interface{}{rpc.BalanceOfAddressArgs{
			Address: address,
		}},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return BalanceOfAddress{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return BalanceOfAddress{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return BalanceOfAddress{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return BalanceOfAddress{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return BalanceOfAddress{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return BalanceOfAddress{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return BalanceOfAddress{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	balanceAddress := rpc.BalanceOfAddressResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return BalanceOfAddress{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &balanceAddress); err != nil {
		return BalanceOfAddress{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return BalanceOfAddress{
		Balance:    balanceAddress.Balance,
		BalanceHex: balanceAddress.BalanceHex,
		Nounce:     balanceAddress.Nounce,
		NextNounce: balanceAddress.NextNounce,
	}, nil
}
