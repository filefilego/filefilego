package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/filefilego/filefilego/rpc"
)

// SendDataQueryRequest sends a data query request.
func (cli *Client) SendDataQueryRequest(ctx context.Context, fileHashes []string) (string, error) {
	if len(fileHashes) == 0 {
		return "", errors.New("empty file hashes")
	}

	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "data_transfer.SendDataQueryRequest",
		Params: []interface{}{rpc.SendDataQueryRequestArgs{
			FileHashes: strings.Join(fileHashes, ","),
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
	responseData := rpc.SendDataQueryRequestResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return "", errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseData); err != nil {
		return "", fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responseData.Hash, nil
}

// CheckDataQueryResponse checks for a data query response.
func (cli *Client) CheckDataQueryResponse(ctx context.Context, dataQueryRequestHash string) (rpc.CheckDataQueryResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "data_transfer.CheckDataQueryResponse",
		Params: []interface{}{rpc.CheckDataQueryResponseArgs{
			DataQueryRequestHash: dataQueryRequestHash,
		}},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.CheckDataQueryResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.CheckDataQueryResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.CheckDataQueryResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.CheckDataQueryResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.CheckDataQueryResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.CheckDataQueryResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.CheckDataQueryResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	responseData := rpc.CheckDataQueryResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.CheckDataQueryResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseData); err != nil {
		return rpc.CheckDataQueryResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responseData, nil
}

// RequestDataQueryResponseFromVerifiers requests data query responses from verifiers.
func (cli *Client) RequestDataQueryResponseFromVerifiers(ctx context.Context, dataQueryRequestHash string) (rpc.CheckDataQueryResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "data_transfer.RequestDataQueryResponseFromVerifiers",
		Params: []interface{}{rpc.CheckDataQueryResponseArgs{
			DataQueryRequestHash: dataQueryRequestHash,
		}},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.CheckDataQueryResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.CheckDataQueryResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.CheckDataQueryResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.CheckDataQueryResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.CheckDataQueryResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.CheckDataQueryResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.CheckDataQueryResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	responseData := rpc.CheckDataQueryResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.CheckDataQueryResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseData); err != nil {
		return rpc.CheckDataQueryResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responseData, nil
}

// DownloadFile requests a file download from file hoster.
func (cli *Client) DownloadFile(ctx context.Context, contractHash, fileHash string, fileSize uint64) (string, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "data_transfer.DownloadFile",
		Params: []interface{}{rpc.DownloadFileArgs{
			ContractHash: contractHash,
			FileHash:     fileHash,
			FileSize:     fileSize,
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
	responseData := rpc.DownloadFileResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return "", errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseData); err != nil {
		return "", fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responseData.Status, nil
}

// DownloadFileProgress reports the file download progress.
func (cli *Client) DownloadFileProgress(ctx context.Context, contractHash, fileHash string) (rpc.DownloadFileProgressResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "data_transfer.DownloadFileProgress",
		Params: []interface{}{rpc.DownloadFileProgressArgs{
			ContractHash: contractHash,
			FileHash:     fileHash,
		}},
		ID: 1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.DownloadFileProgressResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.DownloadFileProgressResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.DownloadFileProgressResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.DownloadFileProgressResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.DownloadFileProgressResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.DownloadFileProgressResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.DownloadFileProgressResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	responseData := rpc.DownloadFileProgressResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.DownloadFileProgressResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseData); err != nil {
		return rpc.DownloadFileProgressResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responseData, nil
}

// SendFileMerkleTreeNodesToVerifier send the files merkle tree nodes to verifier.
func (cli *Client) SendFileMerkleTreeNodesToVerifier(ctx context.Context, contractHash, fileHash string) (bool, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "data_transfer.SendFileMerkleTreeNodesToVerifier",
		Params: []interface{}{rpc.SendFileMerkleTreeNodesToVerifierArgs{
			ContractHash: contractHash,
			FileHash:     fileHash,
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
	responseData := rpc.SendFileMerkleTreeNodesToVerifierResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return false, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseData); err != nil {
		return false, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responseData.Success, nil
}

// RequestEncryptionDataFromVerifierAndDecrypt requests decryption data from verifier and decrypts the files to the provides output paths.
func (cli *Client) RequestEncryptionDataFromVerifierAndDecrypt(ctx context.Context, contractHash string, fileHashes, restoredFilePaths []string) ([]string, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "data_transfer.RequestEncryptionDataFromVerifierAndDecrypt",
		Params: []interface{}{rpc.RequestEncryptionDataFromVerifierArgs{
			ContractHash:      contractHash,
			FileHashes:        fileHashes,
			RestoredFilePaths: restoredFilePaths,
		}},
		ID: 1,
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
	responseData := rpc.RequestEncryptionDataFromVerifierResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return nil, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	if len(responseData.DecryptedFilePaths) == 0 {
		return []string{}, nil
	}

	return responseData.DecryptedFilePaths, nil
}

// SendContractToFileHosterAndVerifier sends a contract to verifier and file hoster.
func (cli *Client) SendContractToFileHosterAndVerifier(ctx context.Context, contractHash string) (bool, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "data_transfer.SendContractToFileHosterAndVerifier",
		Params: []interface{}{rpc.SendContractToFileHosterAndVerifierArgs{
			ContractHash: contractHash,
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
	responseData := rpc.SendContractToFileHosterAndVerifierResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return false, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseData); err != nil {
		return false, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responseData.Success, nil
}

// CreateContractsFromDataQueryResponses creates contract based on the data query responses on this node.
func (cli *Client) CreateContractsFromDataQueryResponses(ctx context.Context, dataQueryRequestHash string) ([]string, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "data_transfer.CreateContractsFromDataQueryResponses",
		Params: []interface{}{rpc.CreateContractsFromDataQueryResponsesArgs{
			DataQueryRequestHash: dataQueryRequestHash,
		}},
		ID: 1,
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
	responseData := rpc.CreateContractsFromDataQueryResponsesResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return nil, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responseData.ContractHashes, nil
}
