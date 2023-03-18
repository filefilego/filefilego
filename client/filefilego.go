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

// GetNodeStats gets the node's stats.
func (cli *Client) GetNodeStats(ctx context.Context) (rpc.StatsResponse, error) {
	payload := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "filefilego.Stats",
		Params:  []interface{}{},
		ID:      1,
	}

	bodyBuf, err := encodeDataToJSON(payload)
	if err != nil {
		return rpc.StatsResponse{}, fmt.Errorf("failed to encode body to json: %w", err)
	}

	req, err := cli.buildRequest(ctx, http.MethodPost, cli.url, bodyBuf, nil)
	if err != nil {
		return rpc.StatsResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return rpc.StatsResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return rpc.StatsResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := JSONRPCResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return rpc.StatsResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return rpc.StatsResponse{}, errors.New(jsonResponse.Error)
	}

	if jsonResponse.Result == nil {
		return rpc.StatsResponse{}, errors.New("empty result in json response")
	}

	// the result contains a map
	// the best way to convert it to a struct is through the json marshal and unmarshal
	responseTx := rpc.StatsResponse{}
	dbByte, err := json.Marshal(jsonResponse.Result)
	if err != nil {
		return rpc.StatsResponse{}, errors.New("failed to marshal the result of response")
	}

	if err := json.Unmarshal(dbByte, &responseTx); err != nil {
		return rpc.StatsResponse{}, fmt.Errorf("failed to unmarshal the result of response back to a struct: %w", err)
	}

	return responseTx, nil
}
