package blockchain

import (
	"os"
	"testing"

	"github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/database"
	"github.com/filefilego/filefilego/internal/transaction"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestNew(t *testing.T) {
	t.Parallel()
	db, err := leveldb.OpenFile("blockchain.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("blockchain.db")
	})
	cases := map[string]struct {
		db     database.Database
		expErr string
	}{
		"no database": {
			expErr: "db is nil",
		},
		"success": {
			db: driver,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			blockchain, err := New(tt.db)
			if tt.expErr != "" {
				assert.Nil(t, blockchain)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, blockchain)
			}
		})
	}
}

func TestSaveAndGetBlockInDB(t *testing.T) {
	db, err := leveldb.OpenFile("savedhain.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("savedhain.db")
	})
	blockchain, err := New(driver)
	assert.NoError(t, err)

	// invalid block
	invalidBlock := block.Block{}
	err = blockchain.SaveBlockInDB(invalidBlock)
	assert.EqualError(t, err, "blockhash is empty")

	// valid block
	validBlock := block.Block{
		Hash:              []byte{1, 2},
		Number:            1,
		PreviousBlockHash: []byte{2},
		Signature:         []byte{1},
		Timestamp:         2,
		Data:              []byte{1},
		Transactions:      []transaction.Transaction{},
	}

	err = blockchain.SaveBlockInDB(validBlock)
	assert.NoError(t, err)

	// get a block with empty hash
	retrivedBlock, err := blockchain.GetBlockByHash(nil)
	assert.EqualError(t, err, "blockhash is empty")
	assert.Empty(t, retrivedBlock.Data)
	assert.Empty(t, retrivedBlock.Transactions)

	// get a block with invalid hash
	retrivedBlock, err = blockchain.GetBlockByHash([]byte{33})
	assert.EqualError(t, err, "failed to get block from database: failed to get value: leveldb: not found")
	assert.Empty(t, retrivedBlock.Data)
	assert.Empty(t, retrivedBlock.Transactions)

	// valid block
	retrivedBlock, err = blockchain.GetBlockByHash(validBlock.Hash)
	assert.NoError(t, err)
	assert.Equal(t, validBlock, retrivedBlock)
}

func TestGetUpdateAddressState(t *testing.T) {
	db, err := leveldb.OpenFile("addressState.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("addressState.db")
	})
	blockchain, err := New(driver)
	assert.NoError(t, err)

	state := AddressState{
		Balance: []byte{1},
		Nounce:  []byte{2},
	}

	// get invalid address
	retrivedState, err := blockchain.GetAddressState([]byte("0x0122"))
	assert.EqualError(t, err, "failed to get address state: failed to get value: leveldb: not found")
	assert.Empty(t, retrivedState)

	// update invalid address
	err = blockchain.UpdateAddressState([]byte{}, state)
	assert.EqualError(t, err, "address is empty")

	// update valid address
	err = blockchain.UpdateAddressState([]byte("0x01"), state)
	assert.NoError(t, err)

	// get valid state
	retrivedState, err = blockchain.GetAddressState([]byte("0x01"))

	assert.NoError(t, err)
	assert.Equal(t, state, retrivedState)
}

func TestMemPoolBlockPoolFunctions(t *testing.T) {
	db, err := leveldb.OpenFile("pool.db", nil)
	assert.NoError(t, err)

	driver, err := database.New(db)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("pool.db")
	})

	blockchain, err := New(driver)
	assert.NoError(t, err)

	transactions := blockchain.GetTransactionsFromPool()
	assert.Len(t, transactions, 0)

	tx := transaction.Transaction{
		Hash:            []byte{10},
		Signature:       []byte{53},
		PublicKey:       []byte{40},
		Nounce:          []byte{50},
		Data:            []byte{20},
		From:            "0x01",
		To:              "0x02",
		Value:           "0x03",
		TransactionFees: "0x04",
		Chain:           []byte{1},
	}
	err = blockchain.PutMemPool(tx)
	assert.NoError(t, err)

	transactions = blockchain.GetTransactionsFromPool()
	assert.Len(t, transactions, 1)
	assert.Equal(t, transactions[0], tx)

	err = blockchain.DeleteFromMemPool(tx)
	assert.NoError(t, err)

	transactions = blockchain.GetTransactionsFromPool()
	assert.Len(t, transactions, 0)

	block := block.Block{
		Hash:              []byte{1},
		Signature:         []byte{12},
		Timestamp:         int64(123),
		Data:              []byte{3},
		PreviousBlockHash: []byte{3},
		Number:            1,
	}

	blocks := blockchain.GetBlocksFromPool()
	assert.Len(t, blocks, 0)
	err = blockchain.PutBlockPool(block)
	assert.NoError(t, err)

	blocks = blockchain.GetBlocksFromPool()
	assert.Len(t, blocks, 1)
	assert.Equal(t, blocks[0], block)

	err = blockchain.DeleteFromBlockPool(block)
	assert.NoError(t, err)

	// delete one more time
	err = blockchain.DeleteFromBlockPool(block)
	assert.NoError(t, err)

	blocks = blockchain.GetBlocksFromPool()
	assert.Len(t, blocks, 0)
}
