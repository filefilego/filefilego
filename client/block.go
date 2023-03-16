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

// GetBlockByNumber get a block by number.
func (cli *Client) GetBlockByNumber(ctx context.Context, blockNumber uint64) (rpc.JSONBlock, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "block.GetByNumber",
		Params: []interface{}{rpc.GetByNumberArgs{
			Number: blockNumber,
		}},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.JSONBlock{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.JSONBlock{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.JSONBlock{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.JSONBlock{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.JSONBlock{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.JSONBlock{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.JSONBlock{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	jsonBlock := rpc.JSONBlock{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.JSONBlock{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &jsonBlock); err != nil {
		return rpc.JSONBlock{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return jsonBlock, nil
}

// GetBlockByHash get a block by hash.
func (cli *Client) GetBlockByHash(ctx context.Context, blockHash string) (rpc.JSONBlock, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "block.GetByHash",
		Params: []interface{}{rpc.GetByHashArgs{
			Hash: blockHash,
		}},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.JSONBlock{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.JSONBlock{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.JSONBlock{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.JSONBlock{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.JSONBlock{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.JSONBlock{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.JSONBlock{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	jsonBlock := rpc.JSONBlock{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.JSONBlock{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &jsonBlock); err != nil {
		return rpc.JSONBlock{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return jsonBlock, nil
}

// GetBlockPool gets the block pool of the node.
func (cli *Client) GetBlockPool(ctx context.Context) (rpc.PoolResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "block.Pool",
		Params:  []interface{}{},
		ID:      1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.PoolResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.PoolResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.PoolResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.PoolResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.PoolResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.PoolResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.PoolResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	jsonBlockPool := rpc.PoolResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.PoolResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &jsonBlockPool); err != nil {
		return rpc.PoolResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return jsonBlockPool, nil
}
