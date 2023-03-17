package client

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSendRawTransaction(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"transaction":{"hash":"0x170e50286de73bd7ff0574e638311e67913e91f76b869e107a5fe202aa745267","signature":"0x3045022100a474a389d079b9503464707626eb9096008a653e0ff77dbb9de465f51e1d180302200473fb01cad94ab3b6c73b54a38c38aa8c078ff7d377cde8a441fa8b800df954","public_key":"0x03fab2023a5b2acb8855085004dc173f67d66df5591afdc3fbc3435880b9c6338b","nounce":"0x1","data":"0x","from":"0xdd9a374e8dce9d656073ec153580301b7d2c3850","to":"0xdd9a374e8dce9d656073ec153580301b7d2c3850","value":"0x22b1c8c1227a00000","transaction_fees":"0x0","chain":"0x01"}},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	tx1 := ` {
        "hash": "0x170e50286de73bd7ff0574e638311e67913e91f76b869e107a5fe202aa745267",
        "signature": "0x3045022100a474a389d079b9503464707626eb9096008a653e0ff77dbb9de465f51e1d180302200473fb01cad94ab3b6c73b54a38c38aa8c078ff7d377cde8a441fa8b800df954",
        "public_key": "0x03fab2023a5b2acb8855085004dc173f67d66df5591afdc3fbc3435880b9c6338b",
        "nounce": "0x1",
        "data": "0x",
        "from": "0xdd9a374e8dce9d656073ec153580301b7d2c3850",
        "to": "0xdd9a374e8dce9d656073ec153580301b7d2c3850",
        "value": "0x22b1c8c1227a00000",
        "transaction_fees": "0x0",
        "chain": "0x01"
      }`

	assert.NoError(t, err)
	tx, err := c.SendRawTransaction(context.TODO(), tx1)
	assert.NoError(t, err)
	assert.Equal(t, "0x170e50286de73bd7ff0574e638311e67913e91f76b869e107a5fe202aa745267", tx.Transaction.Hash)
	assert.Equal(t, "0x1", tx.Transaction.Nounce)
}

func TestSendTransaction(t *testing.T) {
	bodyReader := strings.NewReader(`{"result":{"transaction":{"hash":"0xf4b0094d6259817c47aa8f058fa0e28344b8deb34b2cdbeb71f03f32dc74f932","signature":"0x3044022073f736c561f121ac38ed3c7fb72942256b09468eb66ddd3b2479aa0b5fe407b3022058085f81d1db73c0c60024a9dc906bc237b4286b6aa58b368c348cb7f956ac4f","public_key":"0x026523d733a67ff3f2fe1ac9b26b89ddaa93b2acb3021ff8f839e0bb1950cbbebb","nounce":"0x3","data":"0x00","from":"0x958ef8e7e9c6d4ce25b24b2b61b671d813d77472","to":"0xdd9a374e8dce9d656073ec153580301b7d2c3850","value":"0x22b1c8c1227a00000","transaction_fees":"0x22b1c8c1227a00000","chain":"0x01"}},"error":null,"id":1}`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})

	sendTx := SendTransaction{
		Nounce:          "0x3",
		Data:            "0x00",
		From:            "0x958ef8e7e9c6d4ce25b24b2b61b671d813d77472",
		To:              "0xdd9a374e8dce9d656073ec153580301b7d2c3850",
		Value:           "0x22b1c8c1227a00000",
		TransactionFees: "0x22b1c8c1227a00000",
	}

	assert.NoError(t, err)
	tx, err := c.SendTransaction(context.TODO(), "somejwttoken", sendTx)
	assert.NoError(t, err)
	assert.Equal(t, "0x3", tx.Transaction.Nounce)
}

func TestGetTransactionByAddress(t *testing.T) {
	bodyReader := strings.NewReader(`{ "result": { "transactions": [ { "block_number": 0, "transaction": { "hash": "0x170e50286de73bd7ff0574e638311e67913e91f76b869e107a5fe202aa745267", "signature": "0x3045022100a474a389d079b9503464707626eb9096008a653e0ff77dbb9de465f51e1d180302200473fb01cad94ab3b6c73b54a38c38aa8c078ff7d377cde8a441fa8b800df954", "public_key": "0x03fab2023a5b2acb8855085004dc173f67d66df5591afdc3fbc3435880b9c6338b", "nounce": "0x0", "data": "0x", "from": "0xdd9a374e8dce9d656073ec153580301b7d2c3850", "to": "0xdd9a374e8dce9d656073ec153580301b7d2c3850", "value": "0x22b1c8c1227a00000", "transaction_fees": "0x0", "chain": "0x01" } } ] } }`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	tx, err := c.GetTransactionByAddress(context.TODO(), "0xdd9a374e8dce9d656073ec153580301b7d2c3850")
	assert.NoError(t, err)
	assert.NotEmpty(t, tx.Transactions)
}

func TestGetTransactionByHash(t *testing.T) {
	bodyReader := strings.NewReader(`{ "result": { "transactions": [ { "block_number": 0, "transaction": { "hash": "0x170e50286de73bd7ff0574e638311e67913e91f76b869e107a5fe202aa745267", "signature": "0x3045022100a474a389d079b9503464707626eb9096008a653e0ff77dbb9de465f51e1d180302200473fb01cad94ab3b6c73b54a38c38aa8c078ff7d377cde8a441fa8b800df954", "public_key": "0x03fab2023a5b2acb8855085004dc173f67d66df5591afdc3fbc3435880b9c6338b", "nounce": "0x0", "data": "0x", "from": "0xdd9a374e8dce9d656073ec153580301b7d2c3850", "to": "0xdd9a374e8dce9d656073ec153580301b7d2c3850", "value": "0x22b1c8c1227a00000", "transaction_fees": "0x0", "chain": "0x01" } } ] } }`)
	stringReadCloser := io.NopCloser(bodyReader)
	c, err := New("http://localhost:8090/rpc", &httpClientStub{
		response: &http.Response{
			Body: stringReadCloser,
		},
	})
	assert.NoError(t, err)
	tx, err := c.GetTransactionByHash(context.TODO(), "0x170e50286de73bd7ff0574e638311e67913e91f76b869e107a5fe202aa745267")
	assert.NoError(t, err)
	assert.NotEmpty(t, tx.Transactions)
	assert.Equal(t, "0x170e50286de73bd7ff0574e638311e67913e91f76b869e107a5fe202aa745267", tx.Transactions[0].Transaction.Hash)
}
