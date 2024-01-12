package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// HTTPClient defines the functionality of an HTTP client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client represents the client data.
type Client struct {
	httpClient      HTTPClient
	url             string
	storageEndpoint string
	headers         map[string]string
}

// JSONRPCRequest is the jsonrpc2.0 request.
type JSONRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      uint64        `json:"id"`
}

// JSONRPCResponse is the jsonrpc2.0 response.
type JSONRPCResponse struct {
	Result interface{} `json:"result"`
	Error  string      `json:"error"`
	ID     uint64      `json:"id"`
}

// New creates a new client.
func New(urlEndpoint string, httpClient HTTPClient) (*Client, error) {
	if urlEndpoint == "" {
		return nil, errors.New("url is empty")
	}

	u, err := url.Parse(urlEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}

	if httpClient == nil {
		return nil, errors.New("http client is nil")
	}

	return &Client{
		url:             urlEndpoint,
		storageEndpoint: fmt.Sprintf("%s://%s", u.Scheme, u.Host),
		httpClient:      httpClient,
		headers:         make(map[string]string),
	}, nil
}

// OverrideHTTPHeaders adds headers to all requests.
func (cli *Client) OverrideHTTPHeaders(headers map[string]string) {
	for k, v := range headers {
		cli.headers[k] = v
	}
}

// nolint:unparam
func (cli *Client) buildRequest(ctx context.Context, method, path string, body io.Reader, headers map[string]string) (*http.Request, error) {
	mustHaveBody := method == http.MethodPost || method == http.MethodPut
	if mustHaveBody && body == nil {
		body = bytes.NewReader([]byte{})
	}

	req, err := http.NewRequestWithContext(ctx, method, path, body)
	if err != nil {
		return nil, err
	}

	// set the overrides headers first
	for k, v := range cli.headers {
		req.Header.Set(k, v)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}

func encodeDataToJSON(data interface{}) (*bytes.Buffer, error) {
	params := bytes.NewBuffer(nil)
	if data != nil {
		if err := json.NewEncoder(params).Encode(data); err != nil {
			return nil, err
		}
	}
	return params, nil
}
