package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
)

type tokenResponse struct {
	Token string `json:"token"`
	Error string `json:"error"`
}

// FileUploadResponse represents the uploaded file metadata.
type FileUploadResponse struct {
	Error          string `json:"error"`
	FileName       string `json:"file_name"`
	FileHash       string `json:"file_hash"`
	MerkleRootHash string `json:"merkle_root_hash"`
	Size           int    `json:"size"`
}

// GetStorageAccessToken gets a user access token based on the admin access token to be used for uploading data.
func (cli *Client) GetStorageAccessToken(ctx context.Context, storageAdminToken string) (string, error) {
	req, err := cli.buildRequest(ctx, http.MethodPost, fmt.Sprintf("%s/auth", cli.storageEndpoint), nil, map[string]string{"Authorization": storageAdminToken})
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

	jsonResponse := tokenResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return "", fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return "", errors.New(jsonResponse.Error)
	}

	return jsonResponse.Token, nil
}

// UploadFile uploads a file given the path and storage access token.
func (cli *Client) UploadFile(ctx context.Context, filePath, nodeHash, storageToken string) (FileUploadResponse, error) {
	r, w := io.Pipe()
	m := multipart.NewWriter(w)
	file, err := os.Open(filePath)
	if err != nil {
		return FileUploadResponse{}, fmt.Errorf("failed to open file: %w", err)
	}
	go func() {
		defer w.Close()
		defer m.Close()
		defer file.Close()

		nodeWriter, err := m.CreateFormField("node_hash")
		if err != nil {
			return
		}
		_, _ = nodeWriter.Write([]byte(nodeHash))

		part, err := m.CreateFormFile("file", file.Name())
		if err != nil {
			return
		}
		if _, err = io.Copy(part, file); err != nil {
			return
		}
	}()

	req, err := cli.buildRequest(ctx, http.MethodPost, fmt.Sprintf("%s/uploads", cli.storageEndpoint), r, map[string]string{"Authorization": storageToken, "Content-Type": m.FormDataContentType()})
	if err != nil {
		return FileUploadResponse{}, fmt.Errorf("failed to build request: %w", err)
	}

	response, err := cli.httpClient.Do(req)
	if err != nil {
		return FileUploadResponse{}, fmt.Errorf("failed to do request: %w", err)
	}

	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return FileUploadResponse{}, fmt.Errorf("failed to read response body: %w", err)
	}

	jsonResponse := FileUploadResponse{}
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return FileUploadResponse{}, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if jsonResponse.Error != "" {
		return FileUploadResponse{}, errors.New(jsonResponse.Error)
	}

	return jsonResponse, nil
}
