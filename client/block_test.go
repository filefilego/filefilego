package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetBlockByNumber(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"number":2,"timestamp":1674936587,"data":"0x","previous_block_hash":"0x4d5f150616dffa8fee11fb24e97e3a16e3d820bda193bd4f49d5ef80ad5e2718","hash":"0x0fe492e8cf7cfa81f05b72f10809db7746e204a3a1a591eb2d15ef4d73290a95","signature":"0x3045022100d3cc5bb97bec3c205ed856772104688e60994a898ef678616ee2565c89c8c151022021634359fbf9b205e1f45b532f6c4702f0bcbe085ed8e7ac2a18912e67f64052","merkle_hash":"0x8c612a99487e277612d09f39e701b7a7b63014a0ef95ff3711922b36bb904ff2","transactions":[{"hash":"0x170e50286de73bd7ff0574e638311e67913e91f76b869e107a5fe202aa745267","signature":"0x3045022100a474a389d079b9503464707626eb9096008a653e0ff77dbb9de465f51e1d180302200473fb01cad94ab3b6c73b54a38c38aa8c078ff7d377cde8a441fa8b800df954","public_key":"0x03fab2023a5b2acb8855085004dc173f67d66df5591afdc3fbc3435880b9c6338b","nounce":"0x00","data":"0x","from":"0xdd9a374e8dce9d656073ec153580301b7d2c3850","to":"0xdd9a374e8dce9d656073ec153580301b7d2c3850","value":"0x22b1c8c1227a00000","transaction_fees":"0x0","chain":"0x01"}]},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	block, err := c.GetBlockByNumber(context.TODO(), 2)
	assert.NoError(t, err)
	assert.Equal(t, uint64(2), block.Number)
	assert.Equal(t, "0x0fe492e8cf7cfa81f05b72f10809db7746e204a3a1a591eb2d15ef4d73290a95", block.Hash)
}

func TestGetBlockByHash(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"number":2,"timestamp":1674936587,"data":"0x","previous_block_hash":"0x4d5f150616dffa8fee11fb24e97e3a16e3d820bda193bd4f49d5ef80ad5e2718","hash":"0x0fe492e8cf7cfa81f05b72f10809db7746e204a3a1a591eb2d15ef4d73290a95","signature":"0x3045022100d3cc5bb97bec3c205ed856772104688e60994a898ef678616ee2565c89c8c151022021634359fbf9b205e1f45b532f6c4702f0bcbe085ed8e7ac2a18912e67f64052","merkle_hash":"0x8c612a99487e277612d09f39e701b7a7b63014a0ef95ff3711922b36bb904ff2","transactions":[{"hash":"0x170e50286de73bd7ff0574e638311e67913e91f76b869e107a5fe202aa745267","signature":"0x3045022100a474a389d079b9503464707626eb9096008a653e0ff77dbb9de465f51e1d180302200473fb01cad94ab3b6c73b54a38c38aa8c078ff7d377cde8a441fa8b800df954","public_key":"0x03fab2023a5b2acb8855085004dc173f67d66df5591afdc3fbc3435880b9c6338b","nounce":"0x00","data":"0x","from":"0xdd9a374e8dce9d656073ec153580301b7d2c3850","to":"0xdd9a374e8dce9d656073ec153580301b7d2c3850","value":"0x22b1c8c1227a00000","transaction_fees":"0x0","chain":"0x01"}]},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	block, err := c.GetBlockByHash(context.TODO(), "0x0fe492e8cf7cfa81f05b72f10809db7746e204a3a1a591eb2d15ef4d73290a95")
	assert.NoError(t, err)
	assert.Equal(t, uint64(2), block.Number)
	assert.Equal(t, "0x0fe492e8cf7cfa81f05b72f10809db7746e204a3a1a591eb2d15ef4d73290a95", block.Hash)
}

func TestGetBlocPool(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"block_hashes":[]},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	block, err := c.GetBlockPool(context.TODO())
	assert.NoError(t, err)
	assert.Empty(t, block.BlockHashes)
}
