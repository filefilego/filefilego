package validator

import (
	"os"
	"testing"
	"time"

	"github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/blockchain"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/filefilego/filefilego/internal/database"
	"github.com/filefilego/filefilego/internal/keystore"
	"github.com/filefilego/filefilego/internal/node"
	"github.com/filefilego/filefilego/internal/transaction"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestNew(t *testing.T) {
	t.Parallel()
	kp, err := keystore.NewKey()
	assert.NoError(t, err)
	pubKeyBytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)
	block.SetBlockVerifiers(block.Verifier{
		Address:   kp.Address,
		PublicKey: hexutil.Encode(pubKeyBytes),
	})
	cases := map[string]struct {
		node       NetworkMessagePublisher
		blockchain blockchain.Interface
		privateKey crypto.PrivKey
		expErr     string
	}{
		"empty node": {
			expErr: "node is nil",
		},
		"empty blockchain": {
			node:   &node.Node{},
			expErr: "blockchain is nil",
		},
		"empty privateKey": {
			node:       &node.Node{},
			blockchain: &blockchain.Blockchain{},
			expErr:     "privateKey is nil",
		},
		"success": {
			node:       &node.Node{},
			blockchain: &blockchain.Blockchain{},
			privateKey: kp.PrivateKey,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			miner, err := New(tt.node, tt.blockchain, tt.privateKey)
			if tt.expErr != "" {
				assert.Nil(t, miner)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, miner)
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatorMethods(t *testing.T) {
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)
	genesisHash := make([]byte, len(genesisblockValid.Hash))
	copy(genesisHash, genesisblockValid.Hash)
	db, err := leveldb.OpenFile("testvalidator.bin", nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll("testvalidator.bin")
		// nolint:errcheck
		db.Close()
	})

	blockchainDB, err := database.New(db)
	assert.NoError(t, err)
	bchain, err := blockchain.New(blockchainDB, genesisHash)
	assert.NoError(t, err)
	err = bchain.InitOrLoad()
	assert.NoError(t, err)
	kp, err := keystore.NewKey()
	assert.NoError(t, err)
	pubKeyBytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)
	block.SetBlockVerifiers(block.Verifier{
		Address:   kp.Address,
		PublicKey: hexutil.Encode(pubKeyBytes),
	})
	miner, err := New(&node.Node{}, bchain, kp.PrivateKey)
	assert.NoError(t, err)
	coinbaseTX, err := miner.getCoinbaseTX()
	assert.NoError(t, err)
	assert.NotNil(t, coinbaseTX)
	ok, err := coinbaseTX.Validate()
	assert.NoError(t, err)
	assert.True(t, ok)

	// shouldn't have any transactions
	transactions := miner.prepareMempoolTransactions()
	assert.Len(t, transactions, 0)

	chainID, err := hexutil.Decode("0x01")
	assert.NoError(t, err)
	txCoinbase := transaction.Transaction{
		PublicKey:       pubKeyBytes,
		Nounce:          []byte{0},
		From:            kp.Address,
		To:              kp.Address,
		Value:           "0x22b1c8c1227a00000",
		TransactionFees: "0x0",
		Chain:           chainID,
	}
	err = txCoinbase.Sign(kp.PrivateKey)
	assert.NoError(t, err)
	newBlock := block.Block{
		Timestamp:         time.Now().Unix(),
		PreviousBlockHash: genesisHash,
		Transactions:      []transaction.Transaction{txCoinbase},
		Number:            1,
	}

	err = newBlock.Sign(kp.PrivateKey)
	assert.NoError(t, err)

	err = bchain.PerformStateUpdateFromBlock(newBlock)
	assert.NoError(t, err)

	tx1 := transaction.Transaction{
		PublicKey:       pubKeyBytes,
		Nounce:          []byte{2},
		From:            kp.Address,
		To:              kp.Address,
		Value:           "0x2",
		TransactionFees: "0x1",
		Chain:           chainID,
	}
	err = tx1.Sign(kp.PrivateKey)
	assert.NoError(t, err)
	tx2 := transaction.Transaction{
		PublicKey:       pubKeyBytes,
		Nounce:          []byte{1},
		From:            kp.Address,
		To:              kp.Address,
		Value:           "0x2",
		TransactionFees: "0x1",
		Chain:           chainID,
	}
	err = tx2.Sign(kp.PrivateKey)
	assert.NoError(t, err)

	tx3 := transaction.Transaction{
		PublicKey:       pubKeyBytes,
		Nounce:          []byte{9},
		From:            kp.Address,
		To:              kp.Address,
		Value:           "0x2",
		TransactionFees: "0x1",
		Chain:           chainID,
	}
	err = tx3.Sign(kp.PrivateKey)
	assert.NoError(t, err)

	err = bchain.PutMemPool(tx1)
	assert.NoError(t, err)
	err = bchain.PutMemPool(tx2)
	assert.NoError(t, err)
	err = bchain.PutMemPool(tx3)
	assert.NoError(t, err)
	mempooltransactions := bchain.GetTransactionsFromPool()
	assert.Len(t, mempooltransactions, 3)

	preparedTransactions := miner.prepareMempoolTransactions()
	assert.Len(t, preparedTransactions, 2)

	assert.Equal(t, []byte{1}, preparedTransactions[0].Nounce)
	assert.Equal(t, []byte{2}, preparedTransactions[1].Nounce)

	for _, v := range preparedTransactions {
		err := bchain.DeleteFromMemPool(v)
		assert.NoError(t, err)
	}

	mempooltransactions = bchain.GetTransactionsFromPool()
	assert.Len(t, mempooltransactions, 1)
	assert.Equal(t, []byte{9}, mempooltransactions[0].Nounce)
	assert.Equal(t, uint64(1), bchain.GetHeight())

	// seal a block
	_, err = miner.SealBlock(time.Now().Unix())
	assert.NoError(t, err)
	assert.Equal(t, uint64(2), bchain.GetHeight())

	// one more
	_, err = miner.SealBlock(time.Now().Unix())
	assert.NoError(t, err)
	assert.Equal(t, uint64(3), bchain.GetHeight())

	// one more with past timestamp should give error
	_, err = miner.SealBlock(time.Now().Unix() - 10)
	assert.ErrorContains(t, err, "failed to update blockchain: previous block timestamp")
	assert.Equal(t, uint64(3), bchain.GetHeight())
}

func TestSortTransactionsByNounce(t *testing.T) {
	transactions := []transaction.Transaction{
		{
			From:   "0x1",
			Nounce: []byte{1},
		},
		{
			From:   "0x2",
			Nounce: []byte{5},
		},
		{
			From:   "0x1",
			Nounce: []byte{3},
		},
		{
			From:   "0x2",
			Nounce: []byte{4},
		},
		{
			From:   "0x1",
			Nounce: []byte{2},
		},
	}

	sorted := sortTransactionsByNounce(transactions)
	assert.Len(t, sorted, 5)
	assert.Equal(t, []byte{1}, sorted[0].Nounce)
	assert.Equal(t, []byte{2}, sorted[1].Nounce)
	assert.Equal(t, []byte{3}, sorted[2].Nounce)
	assert.Equal(t, []byte{4}, sorted[3].Nounce)
	assert.Equal(t, []byte{5}, sorted[4].Nounce)

	transactions = []transaction.Transaction{
		{
			From:   "0x1",
			Nounce: []byte{1},
		},
		{
			From:   "0x1",
			Nounce: []byte{5},
		},
	}

	sorted = sortTransactionsByNounce(transactions)
	assert.Len(t, sorted, 2)
	assert.Equal(t, []byte{1}, sorted[0].Nounce)
	assert.Equal(t, []byte{5}, sorted[1].Nounce)
}

func TestPrependTransaction(t *testing.T) {
	transactions := []transaction.Transaction{
		{From: "0x03"},
	}
	assert.Len(t, transactions, 1)
	assert.Equal(t, "0x03", transactions[0].From)
	transactions = prependTransaction(transactions, transaction.Transaction{From: "0x01"})
	assert.Len(t, transactions, 2)
	assert.Equal(t, "0x01", transactions[0].From)
	assert.Equal(t, "0x03", transactions[1].From)
}
