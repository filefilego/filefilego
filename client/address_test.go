package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestListAddresses(t *testing.T) {
	bodyReader := strings.NewReader(`{ "result": { "addresses": ["0x0121123123123123123"] }, "error": null, "id": 143 }`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	addresses, err := c.ListAddresses(context.TODO())
	assert.NoError(t, err)
	assert.Equal(t, "0x0121123123123123123", addresses[0])
}

func TestUnlockAddress(t *testing.T) {
	bodyReader := strings.NewReader(`{ "result": { "token": "tokenvalue" }, "error": null, "id": 143 }`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	token, err := c.UnlockAddress(context.TODO(), "0x958ef8e7e9c6d4ce25b24b2b61b671d813d77472", "123")
	assert.NoError(t, err)
	assert.Equal(t, "tokenvalue", token)
}

func TestLockAddress(t *testing.T) {
	bodyReader := strings.NewReader(`{ "result": { "success": true }, "error": null, "id": 143 }`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	success, err := c.LockAddress(context.TODO(), "0x958ef8e7e9c6d4ce25b24b2b61b671d813d77472", "jwttoken")
	assert.NoError(t, err)
	assert.True(t, success)
}

func TestBalance(t *testing.T) {
	bodyReader := strings.NewReader(`{ "result": { "balance": "0", "balance_hex": "0x0", "nounce": "0x0", "next_nounce": "0x1" }, "error": null, "id": 143 }`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	result, err := c.Balance(context.TODO(), "0x958ef8e7e9c6d4ce25b24b2b61b671d813d77472")
	assert.NoError(t, err)
	assert.Equal(t, "0", result.Balance)
	assert.Equal(t, "0x0", result.BalanceHex)
	assert.Equal(t, "0x0", result.Nounce)
	assert.Equal(t, "0x1", result.NextNounce)
}
