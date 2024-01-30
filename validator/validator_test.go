package validator

import (
	"os"
	"testing"
	"time"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/database"
	"github.com/filefilego/filefilego/keystore"
	"github.com/filefilego/filefilego/node"
	"github.com/filefilego/filefilego/search"
	"github.com/filefilego/filefilego/transaction"
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
		node        NetworkMessagePublisher
		blockchain  blockchain.Interface
		privateKeys []crypto.PrivKey
		expErr      string
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
			expErr:     "privateKeys is empty",
		},
		"success": {
			node:        &node.Node{},
			blockchain:  &blockchain.Blockchain{},
			privateKeys: []crypto.PrivKey{kp.PrivateKey},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			miner, err := New(tt.node, tt.blockchain, tt.privateKeys)
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
	bchain, err := blockchain.New(blockchainDB, &search.Search{}, genesisHash)
	assert.NoError(t, err)
	err = bchain.InitOrLoad(true)
	assert.NoError(t, err)
	kp, err := keystore.NewKey()
	assert.NoError(t, err)
	pubKeyBytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)
	block.SetBlockVerifiers(block.Verifier{
		Address:   kp.Address,
		PublicKey: hexutil.Encode(pubKeyBytes),
	})
	miner, err := New(&node.Node{}, bchain, []crypto.PrivKey{kp.PrivateKey})
	assert.NoError(t, err)
	pk, addr := miner.getPK()
	coinbaseTX, err := miner.getCoinbaseTX(pk, addr)
	assert.NoError(t, err)
	assert.NotNil(t, coinbaseTX)
	ok, err := coinbaseTX.Validate()
	assert.NoError(t, err)
	assert.True(t, ok)

	// shouldn't have any transactions
	transactions := miner.prepareMempoolTransactions()
	assert.Len(t, transactions, 0)

	chainID, err := hexutil.Decode(transaction.ChainID)
	assert.NoError(t, err)

	txCoinbase := transaction.NewTransaction(transaction.LegacyTxType, pubKeyBytes, []byte{0}, []byte{}, kp.Address, kp.Address, "0x22b1c8c1227a00000", "0x0", chainID)

	err = txCoinbase.Sign(kp.PrivateKey)
	assert.NoError(t, err)
	newBlock := block.Block{
		Timestamp:         time.Now().Unix(),
		PreviousBlockHash: genesisHash,
		Transactions:      []transaction.Transaction{*txCoinbase},
		Number:            1,
	}

	err = newBlock.Sign(kp.PrivateKey)
	assert.NoError(t, err)

	err = bchain.PerformStateUpdateFromBlock(newBlock)
	assert.NoError(t, err)

	tx1 := transaction.NewTransaction(transaction.LegacyTxType, pubKeyBytes, []byte{2}, []byte{}, kp.Address, kp.Address, "0x2", "0x1", chainID)

	err = tx1.Sign(kp.PrivateKey)
	assert.NoError(t, err)
	tx2 := transaction.NewTransaction(transaction.LegacyTxType, pubKeyBytes, []byte{1}, []byte{}, kp.Address, kp.Address, "0x2", "0x1", chainID)
	err = tx2.Sign(kp.PrivateKey)
	assert.NoError(t, err)

	tx3 := transaction.NewTransaction(transaction.LegacyTxType, pubKeyBytes, []byte{9}, []byte{}, kp.Address, kp.Address, "0x2", "0x1", chainID)
	err = tx3.Sign(kp.PrivateKey)
	assert.NoError(t, err)

	err = bchain.PutMemPool(*tx1)
	assert.NoError(t, err)
	err = bchain.PutMemPool(*tx2)
	assert.NoError(t, err)
	err = bchain.PutMemPool(*tx3)
	assert.NoError(t, err)
	mempooltransactions := bchain.GetTransactionsFromPool()
	assert.Len(t, mempooltransactions, 3)

	preparedTransactions := miner.prepareMempoolTransactions()
	assert.Len(t, preparedTransactions, 2)

	assert.Equal(t, []byte{1}, preparedTransactions[0].Nounce())
	assert.Equal(t, []byte{2}, preparedTransactions[1].Nounce())

	for _, v := range preparedTransactions {
		err := bchain.DeleteFromMemPool(v)
		assert.NoError(t, err)
	}

	mempooltransactions = bchain.GetTransactionsFromPool()
	assert.Len(t, mempooltransactions, 1)
	assert.Equal(t, []byte{9}, mempooltransactions[0].Nounce())
	assert.Equal(t, uint64(1), bchain.GetHeight())

	// seal a block
	_, _, err = miner.SealBlock(time.Now().Unix())
	assert.NoError(t, err)
	assert.Equal(t, uint64(2), bchain.GetHeight())

	// one more
	_, _, err = miner.SealBlock(time.Now().Unix())
	assert.NoError(t, err)
	assert.Equal(t, uint64(3), bchain.GetHeight())

	// one more with past timestamp should give error
	_, _, err = miner.SealBlock(time.Now().Unix() - 10)
	assert.ErrorContains(t, err, "failed to update blockchain: previous block timestamp")
	assert.Equal(t, uint64(3), bchain.GetHeight())
}

func TestSortTransactionsByNounce(t *testing.T) {
	transactions := []transaction.Transaction{
		*transaction.NewTransaction(transaction.LegacyTxType, nil, []byte{1}, nil, "0x1", "", "0x1", "0x0", []byte{1}),
		*transaction.NewTransaction(transaction.LegacyTxType, nil, []byte{5}, nil, "0x2", "", "0x1", "0x0", []byte{1}),
		*transaction.NewTransaction(transaction.LegacyTxType, nil, []byte{3}, nil, "0x1", "", "0x1", "0x0", []byte{1}),
		*transaction.NewTransaction(transaction.LegacyTxType, nil, []byte{4}, nil, "0x2", "", "0x1", "0x0", []byte{1}),
		*transaction.NewTransaction(transaction.LegacyTxType, nil, []byte{2}, nil, "0x1", "", "0x1", "0x0", []byte{1}),
	}

	sorted := sortTransactionsByNounce(transactions)
	assert.Len(t, sorted, 5)
	assert.Equal(t, []byte{1}, sorted[0].Nounce())
	assert.Equal(t, []byte{2}, sorted[1].Nounce())
	assert.Equal(t, []byte{3}, sorted[2].Nounce())
	assert.Equal(t, []byte{4}, sorted[3].Nounce())
	assert.Equal(t, []byte{5}, sorted[4].Nounce())

	transactions = []transaction.Transaction{
		*transaction.NewTransaction(transaction.LegacyTxType, nil, []byte{1}, nil, "0x1", "", "0x1", "0x0", []byte{1}),
		*transaction.NewTransaction(transaction.LegacyTxType, nil, []byte{5}, nil, "0x1", "", "0x1", "0x0", []byte{1}),
	}

	sorted = sortTransactionsByNounce(transactions)
	assert.Len(t, sorted, 2)
	assert.Equal(t, []byte{1}, sorted[0].Nounce())
	assert.Equal(t, []byte{5}, sorted[1].Nounce())
}

func TestPrependTransaction(t *testing.T) {
	transactions := []transaction.Transaction{
		*transaction.NewTransaction(transaction.LegacyTxType, nil, []byte{1}, nil, "0x3", "", "0x1", "0x0", []byte{1}),
	}
	assert.Len(t, transactions, 1)
	assert.Equal(t, "0x3", transactions[0].From())
	transactions = prependTransaction(transactions, *transaction.NewTransaction(transaction.LegacyTxType, nil, []byte{1}, nil, "0x1", "", "0x1", "0x0", []byte{1}))
	assert.Len(t, transactions, 2)
	assert.Equal(t, "0x1", transactions[0].From())
	assert.Equal(t, "0x3", transactions[1].From())
}
