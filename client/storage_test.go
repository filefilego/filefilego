package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetStorageAccessToken(t *testing.T) {
	bodyReader := strings.NewReader(`{"token": "0x03caedaaae969bcbff331e8c9b36fb444922031a0d041a022b28923339e0e2caf8261da91421c3b1ce5343d9bc54b68223aeba22c7bd36d7e3e44472"}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	token, err := c.GetStorageAccessToken(context.TODO(), "admintoken")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestUploadFile(t *testing.T) {
	bodyReader := strings.NewReader(`{"file_name":"screenshot","file_hash": "02e1474ca120b714d6f382004d8f0dfc3c4cdfec", "merkle_root_hash": "0xf182c7e7050e209cd7c552fed58c33348b52fe884435cd77219c30a73790c842", "size": 614944}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	response, err := c.UploadFile(context.TODO(), "storage.go", "", "sometoken")
	assert.NoError(t, err)
	assert.Equal(t, 614944, response.Size)
	assert.Equal(t, "screenshot", response.FileName)
	assert.Equal(t, "0xf182c7e7050e209cd7c552fed58c33348b52fe884435cd77219c30a73790c842", response.MerkleRootHash)
	assert.Equal(t, "02e1474ca120b714d6f382004d8f0dfc3c4cdfec", response.FileHash)
}
