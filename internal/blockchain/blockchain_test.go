package blockchain

import (
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/filefilego/filefilego/internal/crypto"
	"github.com/filefilego/filefilego/internal/database"
	"github.com/filefilego/filefilego/internal/transaction"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestNew(t *testing.T) {
	t.Parallel()
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)

	db, err := leveldb.OpenFile("blockchain.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("blockchain.db")
	})
	cases := map[string]struct {
		db               database.Database
		genesisBlockHash []byte
		expErr           string
	}{
		"no database": {
			expErr: "db is nil",
		},
		"no genesis block hash": {
			db:     driver,
			expErr: "genesis block hash is empty",
		},
		"success": {
			db:               driver,
			genesisBlockHash: genesisblockValid.Hash,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			blockchain, err := New(tt.db, tt.genesisBlockHash)
			if tt.expErr != "" {
				assert.Nil(t, blockchain)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, blockchain)
			}
		})
	}
}

func TestInitOrLoadAndPerformStateUpdateFromBlock(t *testing.T) {
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)

	db, err := leveldb.OpenFile("init.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("init.db")
	})
	blockchain, err := New(driver, genesisblockValid.Hash)
	assert.NoError(t, err)
	// first run will be init
	err = blockchain.InitOrLoad()
	assert.NoError(t, err)
	genBlock, err := block.GetGenesisBlock()
	assert.NoError(t, err)
	from, err := hexutil.Decode(genBlock.Transactions[0].From)
	assert.NoError(t, err)
	addressState, err := blockchain.GetAddressState(from)
	assert.NoError(t, err)
	balance, err := addressState.GetBalance()
	assert.NoError(t, err)
	assert.Equal(t, "40000000000000000000", balance.String())

	derviedGenesis, err := blockchain.GetBlockByHash(genBlock.Hash)
	assert.NoError(t, err)
	assert.Equal(t, *genBlock, derviedGenesis)
	assert.EqualValues(t, derviedGenesis.Hash, blockchain.GetLastBlockHash())

	// blockchain already has the genesis block
	// add another block to the blockchain with a different verifier
	validBlock2, kp, _ := validBlock(t, 1)
	validBlock2.PreviousBlockHash = make([]byte, len(genBlock.Hash))
	copy(validBlock2.PreviousBlockHash, genBlock.Hash)

	err = validBlock2.Sign(kp.PrivateKey)
	assert.NoError(t, err)
	pubKeyBytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)
	block.BlockVerifiers = append(block.BlockVerifiers, block.Verifier{
		Address:   kp.Address,
		PublicKey: hexutil.Encode(pubKeyBytes),
	})
	err = blockchain.PerformStateUpdateFromBlock(*validBlock2)
	assert.NoError(t, err)
	// from has 39999999999999999999
	from2, err := hexutil.Decode(validBlock2.Transactions[0].From)
	assert.NoError(t, err)
	addressState2, err := blockchain.GetAddressState(from2)
	assert.NoError(t, err)
	balance2, err := addressState2.GetBalance()
	assert.NoError(t, err)
	assert.Equal(t, "39999999999999999999", balance2.String())

	// to has 1
	to2, err := hexutil.Decode(validBlock2.Transactions[1].To)
	assert.NoError(t, err)
	addressState2Addr2, err := blockchain.GetAddressState(to2)
	assert.NoError(t, err)
	balanceofAddr2, err := addressState2Addr2.GetBalance()
	assert.NoError(t, err)
	assert.Equal(t, "1", balanceofAddr2.String())

	// add 3rd block to the chain
	validBlock3, kp, _ := validBlock(t, 2)
	validBlock3.PreviousBlockHash = make([]byte, len(validBlock2.Hash))
	copy(validBlock3.PreviousBlockHash, validBlock2.Hash)

	err = validBlock3.Sign(kp.PrivateKey)
	assert.NoError(t, err)
	pubKeyBytes, err = kp.PublicKey.Raw()
	assert.NoError(t, err)
	block.BlockVerifiers = append(block.BlockVerifiers, block.Verifier{
		Address:   kp.Address,
		PublicKey: hexutil.Encode(pubKeyBytes),
	})
	err = blockchain.PerformStateUpdateFromBlock(*validBlock3)

	assert.NoError(t, err)
	// perform another update with the same block should throw an error
	err = blockchain.PerformStateUpdateFromBlock(*validBlock3)
	assert.EqualError(t, err, "block is already within the blockchain")

	// load and verify blockchain
	// height should be 2
	// last block hash should be validBlock3.Hash
	blockchain2, err := New(driver, genesisblockValid.Hash)
	assert.NoError(t, err)
	err = blockchain2.InitOrLoad()
	assert.NoError(t, err)
	assert.Equal(t, uint64(2), blockchain2.GetHeight())
	assert.EqualValues(t, validBlock3.Hash, blockchain2.GetLastBlockHash())

	err = blockchain.CloseDB()
	assert.NoError(t, err)
}

func TestGetHeightAndIncrement(t *testing.T) {
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)

	db, err := leveldb.OpenFile("height.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("height.db")
	})
	blockchain, err := New(driver, genesisblockValid.Hash)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), blockchain.GetHeight())
	blockchain.IncrementHeightBy(1)
	assert.Equal(t, uint64(1), blockchain.GetHeight())
}

func TestSaveAndGetBlockInDB(t *testing.T) {
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)

	db, err := leveldb.OpenFile("savedhain.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("savedhain.db")
	})
	blockchain, err := New(driver, genesisblockValid.Hash)
	assert.NoError(t, err)

	// invalid block
	invalidBlock := block.Block{}
	err = blockchain.SaveBlockInDB(invalidBlock)
	assert.EqualError(t, err, "blockhash is empty")

	// valid block
	validBlock := block.Block{
		Hash:              []byte{1, 2},
		MerkleHash:        []byte{3, 4},
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
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)
	db, err := leveldb.OpenFile("addressState.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("addressState.db")
	})
	blockchain, err := New(driver, genesisblockValid.Hash)
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
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)
	db, err := leveldb.OpenFile("pool.db", nil)
	assert.NoError(t, err)

	driver, err := database.New(db)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("pool.db")
	})

	blockchain, err := New(driver, genesisblockValid.Hash)
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
		TransactionFees: "0x1",
		Chain:           []byte{1},
	}
	err = blockchain.PutMemPool(tx)
	assert.NoError(t, err)

	// re-add to mempool with errors
	tx.TransactionFees = "f"
	err = blockchain.PutMemPool(tx)
	assert.EqualError(t, err, "failed to decode transaction fees: hex string without 0x prefix")

	// re-add to mempool with higher fee
	tx.TransactionFees = "0x2"
	err = blockchain.PutMemPool(tx)
	assert.NoError(t, err)

	transactions = blockchain.GetTransactionsFromPool()
	assert.Len(t, transactions, 1)
	assert.Equal(t, transactions[0], tx)

	// transaction fee should be the "0x2"
	assert.Equal(t, "0x2", transactions[0].TransactionFees)

	nounce := blockchain.GetNounceFromMemPool([]byte{1})
	assert.Equal(t, uint64(50), nounce)

	err = blockchain.DeleteFromMemPool(tx)
	assert.NoError(t, err)

	transactions = blockchain.GetTransactionsFromPool()
	assert.Len(t, transactions, 0)

	block := block.Block{
		Hash:              []byte{1},
		MerkleHash:        []byte{2},
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

	accountAddr := []byte{12}
	amount := big.NewInt(10)
	err = blockchain.addBalanceTo(accountAddr, amount)
	assert.NoError(t, err)
	newState, err := blockchain.GetAddressState(accountAddr)
	assert.NoError(t, err)

	newStateBalance, err := newState.GetBalance()
	assert.NoError(t, err)
	assert.EqualValues(t, amount.Bytes(), newStateBalance.Bytes())
	assert.Equal(t, "10", newStateBalance.String())

	// subtract a bigger amount than what is in db
	err = blockchain.subBalanceFrom(accountAddr, amount.Add(amount, amount), 10)
	assert.EqualError(t, err, "failed to subtract: amount is greater than balance")

	// subtract the right amount
	err = blockchain.subBalanceFrom(accountAddr, big.NewInt(10), 11)
	assert.NoError(t, err)

	// balance should be zero
	newState, err = blockchain.GetAddressState(accountAddr)
	assert.NoError(t, err)
	zeroBalance, err := newState.GetBalance()
	assert.NoError(t, err)
	assert.Equal(t, "0", zeroBalance.String())
	derivedNounce, err := newState.GetNounce()
	assert.NoError(t, err)
	assert.Equal(t, uint64(11), derivedNounce)

	// add a negative big int
	negativeBig := big.NewInt(-10)
	err = blockchain.addBalanceTo(accountAddr, negativeBig)
	assert.EqualError(t, err, "amount is negative")
	newState, err = blockchain.GetAddressState(accountAddr)
	assert.NoError(t, err)
	newBalance, err := newState.GetBalance()
	assert.NoError(t, err)
	assert.Equal(t, "0", newBalance.String())

	// subtract negative
	err = blockchain.subBalanceFrom(accountAddr, negativeBig, 12)
	assert.EqualError(t, err, "amount is negative")

	err = blockchain.CloseDB()
	assert.NoError(t, err)
}

func TestPerformAddressStateUpdate(t *testing.T) {
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)
	db, err := leveldb.OpenFile("internalmutation.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("internalmutation.db")
	})
	blockchain, err := New(driver, genesisblockValid.Hash)
	assert.NoError(t, err)
	validBlock, kp, kp2 := validBlock(t, 0)
	err = validBlock.Sign(kp.PrivateKey)
	assert.NoError(t, err)

	verifierAddr, err := hexutil.Decode(kp.Address)
	assert.NoError(t, err)

	// update the list of verifiers
	pubKeyBytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)
	block.BlockVerifiers = append(block.BlockVerifiers, block.Verifier{
		Address:   kp.Address,
		PublicKey: hexutil.Encode(pubKeyBytes),
	})

	coinbaseTx, err := validBlock.GetAndValidateCoinbaseTransaction()
	assert.NoError(t, err)

	ok, err := validBlock.Validate()
	assert.NoError(t, err)
	assert.True(t, ok)

	for _, v := range validBlock.Transactions {
		isCoinbase, _ := coinbaseTx.Equals(v)
		err := blockchain.PerformAddressStateUpdate(v, verifierAddr, isCoinbase)
		assert.NoError(t, err)
	}

	addressState, err := blockchain.GetAddressState(verifierAddr)
	assert.NoError(t, err)

	addressBalance, err := addressState.GetBalance()
	assert.NoError(t, err)

	// balance should have tx value + tx fees
	// coinbase tx contains hex of 40999999999999999999 and 0x0 for tx value and fees
	// address should have 39999999999999999999 since we send another tx with value of 0x1 and transaction fee of 0x1
	// but we send back the 0x1 fee to the verfier
	assert.Equal(t, "39999999999999999999", addressBalance.String())

	address2Bytes, err := hexutil.Decode(kp2.Address)
	assert.NoError(t, err)
	stateOfSecondAddr, err := blockchain.GetAddressState(address2Bytes)
	assert.NoError(t, err)
	balanceOfSecond, err := stateOfSecondAddr.GetBalance()
	assert.NoError(t, err)
	assert.Equal(t, "1", balanceOfSecond.String())

	assert.NoError(t, blockchain.CloseDB())
}

// generate a block and propagate the keypair used for the tx
func validBlock(t *testing.T, blockNumber uint64) (*block.Block, crypto.KeyPair, crypto.KeyPair) {
	coinbasetx, kp := validTransaction(t)
	err := coinbasetx.Sign(kp.PrivateKey)
	assert.NoError(t, err)

	validTx2, kp2 := validTransaction(t)
	validTx2.PublicKey, err = kp.PublicKey.Raw()
	assert.NoError(t, err)
	validTx2.From = kp.Address
	validTx2.To = kp2.Address
	validTx2.TransactionFees = "0x1"
	validTx2.Value = "0x1"
	validTx2.Nounce = []byte{1}
	err = validTx2.Sign(kp.PrivateKey)
	assert.NoError(t, err)

	b := block.Block{
		Timestamp:         time.Now().Unix(),
		Data:              []byte{1},
		PreviousBlockHash: []byte{1, 1},
		Transactions: []transaction.Transaction{
			// its a coinbase tx
			*coinbasetx,
			*validTx2,
		},
		Number: blockNumber,
	}

	return &b, kp, kp2
}

// generate a keypair and use it to sign tx
func validTransaction(t *testing.T) (*transaction.Transaction, crypto.KeyPair) {
	keypair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	pkyData, err := keypair.PublicKey.Raw()
	assert.NoError(t, err)

	mainChain, err := hexutil.Decode("0x01")
	assert.NoError(t, err)

	addr, err := crypto.RawPublicToAddress(pkyData)
	assert.NoError(t, err)

	tx := transaction.Transaction{
		PublicKey:       pkyData,
		Nounce:          []byte{0},
		Data:            []byte{1},
		From:            addr,
		To:              addr,
		Chain:           mainChain,
		Value:           "0x22b1c8c1227a00000",
		TransactionFees: "0x0",
	}
	assert.NoError(t, err)
	return &tx, keypair
}
