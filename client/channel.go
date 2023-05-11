package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/filefilego/filefilego/rpc"
	"github.com/filefilego/filefilego/search"
)

// CreateChannelNodeItemsDataPayload creates the transaction data payload given the channel node items list.
func (cli *Client) CreateChannelNodeItemsTxDataPayload(ctx context.Context, nodes []rpc.NodeItemJSON) (string, string, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "channel.CreateNodeItemsTxDataPayload",
		Params: []interface{}{
			rpc.CreateNodeItemsTxDataPayloadArgs{
				Nodes: nodes,
			},
		},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return "", "", fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return "", "", errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return "", "", errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	responsePayload := rpc.CreateNodeItemsTxDataPayloadResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return "", "", errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responsePayload); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responsePayload.TransactionDataPayloadHex, responsePayload.TotalFeesRequired, nil
}

// ListChannels gets the list of channels.
func (cli *Client) ListChannels(ctx context.Context, currentPage, pageSize int, order string) (rpc.ListResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "channel.List",
		Params: []interface{}{
			rpc.ListArgs{
				CurrentPage: currentPage,
				PageSize:    pageSize,
				Order:       order,
			},
		},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.ListResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.ListResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.ListResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.ListResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.ListResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.ListResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.ListResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	responsePayload := rpc.ListResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.ListResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responsePayload); err != nil {
		return rpc.ListResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responsePayload, nil
}

// SearchChannels search channel items.
func (cli *Client) SearchChannels(ctx context.Context, query string, searchType search.Type, size, currentPage int) (rpc.SearchResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "channel.Search",
		Params: []interface{}{
			rpc.SearchArgs{
				Query:       query,
				SearchType:  string(searchType),
				Size:        size,
				CurrentPage: currentPage,
			},
		},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.SearchResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.SearchResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.SearchResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.SearchResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.SearchResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.SearchResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.SearchResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	responsePayload := rpc.SearchResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.SearchResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responsePayload); err != nil {
		return rpc.SearchResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responsePayload, nil
}

// GetChannelNodeItem gets channel node item.
func (cli *Client) GetChannelNodeItem(ctx context.Context, nodeHash string) (rpc.GetNodeItemResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "channel.GetNodeItem",
		Params: []interface{}{
			rpc.GetNodeItemArgs{
				NodeHash: nodeHash,
			},
		},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.GetNodeItemResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.GetNodeItemResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.GetNodeItemResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.GetNodeItemResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.GetNodeItemResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.GetNodeItemResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.GetNodeItemResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	responsePayload := rpc.GetNodeItemResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.GetNodeItemResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responsePayload); err != nil {
		return rpc.GetNodeItemResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responsePayload, nil
}

// ChannelFilesFromEntryOrFolder gets a list of files recursively under an entry or a directory.
func (cli *Client) ChannelFilesFromEntryOrFolder(ctx context.Context, nodeHash string) (rpc.FilesFromEntryOrFolderResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "channel.FilesFromEntryOrFolder",
		Params: []interface{}{
			rpc.FilesFromEntryOrFolderArgs{
				NodeHash: nodeHash,
			},
		},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.FilesFromEntryOrFolderResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.FilesFromEntryOrFolderResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.FilesFromEntryOrFolderResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.FilesFromEntryOrFolderResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.FilesFromEntryOrFolderResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.FilesFromEntryOrFolderResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.FilesFromEntryOrFolderResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	responsePayload := rpc.FilesFromEntryOrFolderResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.FilesFromEntryOrFolderResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responsePayload); err != nil {
		return rpc.FilesFromEntryOrFolderResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responsePayload, nil
}
