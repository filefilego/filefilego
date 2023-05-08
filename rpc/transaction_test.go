package rpc

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/keystore"
	"github.com/filefilego/filefilego/node"
	transaction "github.com/filefilego/filefilego/transaction"
	"github.com/stretchr/testify/assert"
)

func TestNewTransactionAPI(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		keystore   keystore.KeyAuthorizer
		publisher  NetworkMessagePublisher
		blockchain Blockchain
		expErr     string
	}{
		"no keystore": {
			expErr: "keystore is nil",
		},
		"no publisher": {
			keystore: &keystore.Store{},
			expErr:   "publisher is nil",
		},
		"no blockchain": {
			keystore:  &keystore.Store{},
			publisher: &node.Node{},
			expErr:    "blockchain is nil",
		},
		"success": {
			keystore:   &keystore.Store{},
			publisher:  &node.Node{},
			blockchain: &blockchain.Blockchain{},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, err := NewTransactionAPI(tt.keystore, tt.publisher, tt.blockchain, false)
			if tt.expErr != "" {
				assert.Nil(t, api)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, api)
				assert.NoError(t, err)
			}
		})
	}
}

func TestTransactionAPIMethods(t *testing.T) {
	k, err := keystore.NewKey()
	accessToken := "123456789"
	assert.NoError(t, err)

	unlockedKey := keystore.UnlockedKey{
		Key: k,
		JWT: accessToken,
	}
	ks := keyAuthorizerStub{ok: true, key: unlockedKey}

	bchain := &blockchainStub{}
	transactionAPI, err := NewTransactionAPI(&ks, &networkMessagePublisherStub{}, bchain, false)
	assert.NoError(t, err)

	validTx, kp := validTransaction(t)
	err = validTx.Sign(kp.PrivateKey)
	assert.NoError(t, err)
	jsonTx := toJSONTransaction(*validTx)
	jsonTxBytes, err := json.Marshal(jsonTx)
	assert.NoError(t, err)
	sendRawArgs := &SendRawTransactionArgs{
		RawTransaction: string(jsonTxBytes),
	}
	// SendRawTransaction
	sendRawResponse := &TransactionResponse{}
	err = transactionAPI.SendRawTransaction(&http.Request{}, sendRawArgs, sendRawResponse)
	assert.NoError(t, err)
	assert.Equal(t, jsonTx.Chain, sendRawResponse.Transaction.Chain)
	assert.Equal(t, jsonTx.Data, sendRawResponse.Transaction.Data)
	assert.Equal(t, jsonTx.From, sendRawResponse.Transaction.From)
	assert.Equal(t, jsonTx.Hash, sendRawResponse.Transaction.Hash)
	assert.Equal(t, jsonTx.Nounce, sendRawResponse.Transaction.Nounce)
	assert.Equal(t, jsonTx.PublicKey, sendRawResponse.Transaction.PublicKey)
	assert.Equal(t, jsonTx.Signature, sendRawResponse.Transaction.Signature)
	assert.Equal(t, jsonTx.To, sendRawResponse.Transaction.To)
	assert.Equal(t, jsonTx.TransactionFees, sendRawResponse.Transaction.TransactionFees)
	assert.Equal(t, jsonTx.Value, sendRawResponse.Transaction.Value)

	// another raw tx
	rawTX := `{"hash":"0xf843eb3045484c198a23ad19949dd31f1f01b00087c92895dadce0c7e31984b9","signature":"0x3045022100d2c6c2be2710d2e8f681a8410aad884efb39dbc9c398c574627e9f7455399322022043dcff73e0ccbe307cc8e9fb93daf40c43c0c3a14e308150515ce8bbc65b83e9","public_key":"0x02b4dbfc4d1c008687cb34b9bc736de86eace1a6a67f7248cdaacf7fb4cf548e8a","nounce":"0x1","data":"0x01","from":"0xc47418d2af83b80f10691434601474efd0549f6d","to":"0xbd372b1188350a99d433cec50f80f058bb9a614c","value":"0x1","transaction_fees":"0x1","chain":"0x01"}`
	sendRawArgs2 := &SendRawTransactionArgs{
		RawTransaction: rawTX,
	}
	// SendRawTransaction
	sendRawResponse2 := &TransactionResponse{}
	err = transactionAPI.SendRawTransaction(&http.Request{}, sendRawArgs2, sendRawResponse2)
	assert.NoError(t, err)

	// wrong access token
	sendTransactionArgs := &SendTransactionArgs{
		AccessToken:     accessToken,
		Nounce:          jsonTx.Nounce,
		Data:            jsonTx.Data,
		From:            k.Address,
		To:              jsonTx.To,
		Value:           jsonTx.Value,
		TransactionFees: jsonTx.TransactionFees,
	}

	sendTransactionResponse := &TransactionResponse{}
	err = transactionAPI.SendTransaction(&http.Request{}, sendTransactionArgs, sendTransactionResponse)
	assert.NoError(t, err)
	assert.Equal(t, jsonTx.Chain, sendTransactionResponse.Transaction.Chain)
	assert.Equal(t, jsonTx.Data, sendTransactionResponse.Transaction.Data)
	assert.Equal(t, k.Address, sendTransactionResponse.Transaction.From)
	assert.Equal(t, jsonTx.Nounce, sendTransactionResponse.Transaction.Nounce)
	assert.Equal(t, jsonTx.To, sendTransactionResponse.Transaction.To)
	assert.Equal(t, jsonTx.TransactionFees, sendTransactionResponse.Transaction.TransactionFees)
	assert.Equal(t, jsonTx.Value, sendTransactionResponse.Transaction.Value)

	// Pool
	memPoolResponse := &MemPoolResponse{}
	err = transactionAPI.Pool(&http.Request{}, &EmptyArgs{}, memPoolResponse)
	assert.NoError(t, err)
	assert.Empty(t, memPoolResponse.TransactionHashes)
	bchain.mempool = []transaction.Transaction{*validTx}
	err = transactionAPI.Pool(&http.Request{}, &EmptyArgs{}, memPoolResponse)
	assert.NoError(t, err)
	assert.NotEmpty(t, memPoolResponse.TransactionHashes)

	// Receipt
	receiptArgs := &ReceiptArgs{Hash: hexutil.Encode(validTx.Hash)}
	transactionsResponse := &TransactionsResponse{}
	bchain.addressTransactions = []transaction.Transaction{*validTx}
	bchain.addressTransactionsBlockNumbers = []uint64{5}
	bchain.addressTransactionsTimestamps = []int64{time.Now().Unix()}

	err = transactionAPI.Receipt(&http.Request{}, receiptArgs, transactionsResponse)
	assert.NoError(t, err)
	assert.Equal(t, jsonTx, transactionsResponse.Transactions[0].Transaction)
	assert.Equal(t, uint64(5), transactionsResponse.Transactions[0].BlockNumber)

	// ByAddress
	// empty address
	byAddressArgs := &ByAddressArgs{}
	byAddressResponse := &TransactionsResponse{}
	err = transactionAPI.ByAddress(&http.Request{}, byAddressArgs, byAddressResponse)
	assert.EqualError(t, err, "input is empty")

	byAddressArgs.Address = jsonTx.From
	err = transactionAPI.ByAddress(&http.Request{}, byAddressArgs, byAddressResponse)
	assert.NoError(t, err)
	assert.Equal(t, jsonTx, byAddressResponse.Transactions[0].Transaction)
	assert.Equal(t, uint64(5), byAddressResponse.Transactions[0].BlockNumber)
}

type keyAuthorizerStub struct {
	ok  bool
	key keystore.UnlockedKey
	err error
}

func (k *keyAuthorizerStub) Authorized(jwtToken string) (bool, keystore.UnlockedKey, error) {
	return k.ok, k.key, k.err
}

type networkMessagePublisherStub struct {
	err error
}

func (n *networkMessagePublisherStub) PublishMessageToNetwork(ctx context.Context, topicName string, data []byte) error {
	return n.err
}

type blockchainStub struct {
	// PutMemPool
	memPoolPutErr error

	// GetTransactionsFromPool
	mempool []transaction.Transaction

	// GetAddressTransactions
	addressTransactions             []transaction.Transaction
	addressTransactionsBlockNumbers []uint64
	addressTransactionsTimestamps   []int64
	addressTransactionsErr          error
}

func (b *blockchainStub) PutMemPool(tx transaction.Transaction) error {
	return b.memPoolPutErr
}

func (b *blockchainStub) GetTransactionsFromPool() []transaction.Transaction {
	return b.mempool
}

func (b *blockchainStub) GetAddressTransactions(address []byte, currentPage, limit int) ([]transaction.Transaction, []uint64, []int64, error) {
	return b.addressTransactions, b.addressTransactionsBlockNumbers, b.addressTransactionsTimestamps, b.addressTransactionsErr
}

func (b *blockchainStub) GetTransactionByHash(hash []byte) ([]transaction.Transaction, []uint64, error) {
	return b.addressTransactions, b.addressTransactionsBlockNumbers, b.addressTransactionsErr
}
