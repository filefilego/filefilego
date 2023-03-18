package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendDataQueryRequest(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"hash":"0x0585084bc6e0c76af2d4b7f19e6020126df140bb6cd2975b5057aae40a2b2eae"},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	hashDataQuery, err := c.SendDataQueryRequest(context.TODO(), []string{"01", "02"})
	assert.NoError(t, err)
	assert.NotEmpty(t, hashDataQuery)
}

func TestCheckDataQueryResponse(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"responses":[{"from_peer_addr":"peerid1"}]},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	response, err := c.CheckDataQueryResponse(context.TODO(), "0x0585084bc6e0c76af2d4b7f19e6020126df140bb6cd2975b5057aae40a2b2eae")
	assert.NoError(t, err)
	assert.NotEmpty(t, response.Responses)
	assert.Equal(t, "peerid1", response.Responses[0].FromPeerAddr)
}

func TestRequestDataQueryResponseFromVerifiers(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"responses":[{"from_peer_addr":"peerid1"}]},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	response, err := c.RequestDataQueryResponseFromVerifiers(context.TODO(), "0x0585084bc6e0c76af2d4b7f19e6020126df140bb6cd2975b5057aae40a2b2eae")
	assert.NoError(t, err)
	assert.NotEmpty(t, response.Responses)
	assert.Equal(t, "peerid1", response.Responses[0].FromPeerAddr)
}

func TestDownloadFile(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"status":"started"},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	status, err := c.DownloadFile(context.TODO(), "0x0585084bc6e0c76af2d4b7f19e6020126df140bb6cd2975b5057aae40a2b2eae", "0585084bc6e0c76af2d4b7f19e6020126d", 123224)
	assert.NoError(t, err)
	assert.Equal(t, "started", status)
}

func TestDownloadFileProgress(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"bytes_transfered":32242, "error":""},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	status, err := c.DownloadFileProgress(context.TODO(), "0x0585084bc6e0c76af2d4b7f19e6020126df140bb6cd2975b5057aae40a2b2eae", "0585084bc6e0c76af2d4b7f19e6020126d")
	assert.NoError(t, err)
	assert.Equal(t, uint64(32242), status.BytesTransfered)
}

func TestSendFileMerkleTreeNodesToVerifier(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"success":true},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	ok, err := c.SendFileMerkleTreeNodesToVerifier(context.TODO(), "0x0585084bc6e0c76af2d4b7f19e6020126df140bb6cd2975b5057aae40a2b2eae", "0585084bc6e0c76af2d4b7f19e6020126d")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestSendRequestEncryptionDataFromVerifierAndDecrypt(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"decrypted_file_paths":["/home/output.txt"]},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	outputFiles, err := c.RequestEncryptionDataFromVerifierAndDecrypt(context.TODO(), "0x0585084bc6e0c76af2d4b7f19e6020126df140bb6cd2975b5057aae40a2b2eae", []string{"01"}, []string{"output.txt"})
	assert.NoError(t, err)
	assert.NotEmpty(t, outputFiles)
	assert.Equal(t, "/home/output.txt", outputFiles[0])
}

func TestSendContractToFileHosterAndVerifier(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"success":true},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	ok, err := c.SendContractToFileHosterAndVerifier(context.TODO(), "0x0585084bc6e0c76af2d4b7f19e6020126df140bb6cd2975b5057aae40a2b2eae")
	assert.NoError(t, err)
	assert.True(t, ok)
}

func TestCreateContractsFromDataQueryResponses(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"contract_hashes":["0x1232"]},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	contractHashes, err := c.CreateContractsFromDataQueryResponses(context.TODO(), "0x0585084bc6e0c76af2d4b7f19e6020126df140bb6cd2975b5057aae40a2b2eae")
	assert.NoError(t, err)
	assert.NotEmpty(t, contractHashes)
	assert.Equal(t, "0x1232", contractHashes[0])
}