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

// SendTransaction represents a tx to be sent to the network.
type SendTransaction struct {
	Nounce          string
	Data            string
	From            string
	To              string
	Value           string
	TransactionFees string
}

// SendRawTransaction sends a raw transaction.
func (cli *Client) SendRawTransaction(ctx context.Context, jsonEncodedTransactionBytes string) (rpc.TransactionResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "transaction.SendRawTransaction",
		Params: []interface{}{rpc.SendRawTransactionArgs{
			RawTransaction: jsonEncodedTransactionBytes,
		}},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.TransactionResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.TransactionResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.TransactionResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.TransactionResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.TransactionResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.TransactionResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.TransactionResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	tx := rpc.TransactionResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.TransactionResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &tx); err != nil {
		return rpc.TransactionResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return tx, nil
}

// SendTransaction sends a transaction.
// this method requires the address to be unlocked and a token supplied
func (cli *Client) SendTransaction(ctx context.Context, token string, tx SendTransaction) (rpc.TransactionResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "transaction.SendTransaction",
		Params: []interface{}{rpc.SendTransactionArgs{
			AccessToken:     token,
			Nounce:          tx.Nounce,
			Data:            tx.Data,
			From:            tx.From,
			To:              tx.To,
			Value:           tx.Value,
			TransactionFees: tx.TransactionFees,
		}},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.TransactionResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.TransactionResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.TransactionResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.TransactionResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.TransactionResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.TransactionResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.TransactionResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	responseTx := rpc.TransactionResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.TransactionResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseTx); err != nil {
		return rpc.TransactionResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responseTx, nil
}

// TransactionPool returns the transaction in the tx pool
func (cli *Client) TransactionPool(ctx context.Context, token string, tx SendTransaction) (rpc.MemPoolResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "transaction.Pool",
		Params:  []interface{}{},
		ID:      1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.MemPoolResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.MemPoolResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.MemPoolResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.MemPoolResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.MemPoolResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.MemPoolResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.MemPoolResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	responseTx := rpc.MemPoolResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.MemPoolResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseTx); err != nil {
		return rpc.MemPoolResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responseTx, nil
}

// GetTransactionByAddress given transactions of an address.
func (cli *Client) GetTransactionByAddress(ctx context.Context, address string, currentPage, limit int) (rpc.TransactionsResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "transaction.ByAddress",
		Params: []interface{}{rpc.ByAddressArgs{
			Address:     address,
			CurrentPage: currentPage,
			Limit:       limit,
		}},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.TransactionsResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.TransactionsResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.TransactionsResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.TransactionsResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.TransactionsResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.TransactionsResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.TransactionsResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	responseTx := rpc.TransactionsResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.TransactionsResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseTx); err != nil {
		return rpc.TransactionsResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responseTx, nil
}

// GetTransactionByHash given transactions hash returns the transaction data and block number.
func (cli *Client) GetTransactionByHash(ctx context.Context, transactionHash string) (rpc.TransactionsResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "transaction.Receipt",
		Params: []interface{}{rpc.GetByHashArgs{
			Hash: transactionHash,
		}},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.TransactionsResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.TransactionsResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.TransactionsResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.TransactionsResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.TransactionsResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.TransactionsResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.TransactionsResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	responseTx := rpc.TransactionsResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.TransactionsResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseTx); err != nil {
		return rpc.TransactionsResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responseTx, nil
}
