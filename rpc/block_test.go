package rpc

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/database"
	"github.com/filefilego/filefilego/search"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestNewBlockAPI(t *testing.T) {
	api, err := NewBlockAPI(nil)
	assert.EqualError(t, err, "blockchain is nil")
	assert.Nil(t, api)
}

func TestBlockAPIMethods(t *testing.T) {
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)

	db, err := leveldb.OpenFile("blockapi.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("blockapi.db")
	})
	blockchain, err := blockchain.New(driver, &search.Search{}, genesisblockValid.Hash)
	assert.NoError(t, err)
	err = blockchain.InitOrLoad()
	assert.NoError(t, err)
	api, err := NewBlockAPI(blockchain)
	assert.NoError(t, err)

	// GetByNumber
	args := &GetByNumberArgs{}
	response := &JSONBlock{}
	args.Number = 0
	err = api.GetByNumber(&http.Request{}, args, response)
	assert.NoError(t, err)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Hash), response.Hash)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Data), response.Data)
	assert.Equal(t, hexutil.Encode(genesisblockValid.MerkleHash), response.MerkleHash)
	assert.Equal(t, hexutil.Encode(genesisblockValid.PreviousBlockHash), response.PreviousBlockHash)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Signature), response.Signature)
	assert.Equal(t, genesisblockValid.Number, response.Number)
	assert.Equal(t, genesisblockValid.Timestamp, response.Timestamp)
	assert.Len(t, response.Transactions, 1)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Transactions[0].Chain), response.Transactions[0].Chain)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Transactions[0].Data), response.Transactions[0].Data)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Transactions[0].Hash), response.Transactions[0].Hash)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Transactions[0].Nounce), response.Transactions[0].Nounce)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Transactions[0].PublicKey), response.Transactions[0].PublicKey)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Transactions[0].Signature), response.Transactions[0].Signature)
	assert.Equal(t, genesisblockValid.Transactions[0].From, response.Transactions[0].From)
	assert.Equal(t, genesisblockValid.Transactions[0].To, response.Transactions[0].To)
	assert.Equal(t, genesisblockValid.Transactions[0].Value, response.Transactions[0].Value)
	assert.Equal(t, genesisblockValid.Transactions[0].TransactionFees, response.Transactions[0].TransactionFees)

	// GetByHash
	args2 := &GetByHashArgs{}
	response2 := &JSONBlock{}
	err = api.GetByHash(&http.Request{}, args2, response2)
	assert.EqualError(t, err, "input is empty")
	args2.Hash = hexutil.Encode(genesisblockValid.Hash)
	err = api.GetByHash(&http.Request{}, args2, response2)
	assert.NoError(t, err)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Hash), response2.Hash)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Data), response2.Data)
	assert.Equal(t, hexutil.Encode(genesisblockValid.MerkleHash), response2.MerkleHash)
	assert.Equal(t, hexutil.Encode(genesisblockValid.PreviousBlockHash), response2.PreviousBlockHash)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Signature), response2.Signature)
	assert.Equal(t, genesisblockValid.Number, response2.Number)
	assert.Equal(t, genesisblockValid.Timestamp, response2.Timestamp)
	assert.Len(t, response2.Transactions, 1)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Transactions[0].Chain), response2.Transactions[0].Chain)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Transactions[0].Data), response2.Transactions[0].Data)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Transactions[0].Hash), response2.Transactions[0].Hash)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Transactions[0].Nounce), response2.Transactions[0].Nounce)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Transactions[0].PublicKey), response2.Transactions[0].PublicKey)
	assert.Equal(t, hexutil.Encode(genesisblockValid.Transactions[0].Signature), response2.Transactions[0].Signature)
	assert.Equal(t, genesisblockValid.Transactions[0].From, response2.Transactions[0].From)
	assert.Equal(t, genesisblockValid.Transactions[0].To, response2.Transactions[0].To)
	assert.Equal(t, genesisblockValid.Transactions[0].Value, response2.Transactions[0].Value)
	assert.Equal(t, genesisblockValid.Transactions[0].TransactionFees, response2.Transactions[0].TransactionFees)

	// Pool
	response3 := &PoolResponse{}
	err = api.Pool(&http.Request{}, &EmptyArgs{}, response3)
	assert.NoError(t, err)
	assert.Empty(t, response3.BlockHashes)
	futureBlock := block.Block{
		Hash:              []byte{1},
		MerkleHash:        []byte{2},
		Signature:         []byte{3},
		Timestamp:         time.Now().Unix(),
		Data:              []byte{},
		PreviousBlockHash: []byte{33},
		Transactions:      genesisblockValid.Transactions,
		Number:            333,
	}

	err = blockchain.PutBlockPool(futureBlock)
	assert.NoError(t, err)
	err = api.Pool(&http.Request{}, &EmptyArgs{}, response3)
	assert.NoError(t, err)
	assert.Len(t, response3.BlockHashes, 1)
	assert.Equal(t, "0x01", response3.BlockHashes[0])
}
