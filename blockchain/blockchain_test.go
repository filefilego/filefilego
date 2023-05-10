package blockchain

import (
	"bytes"
	"context"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/common/currency"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/database"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/filefilego/filefilego/search"
	"github.com/filefilego/filefilego/transaction"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
	"google.golang.org/protobuf/proto"
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
		search           search.IndexSearcher
		genesisBlockHash []byte
		expErr           string
	}{
		"no database": {
			expErr: "db is nil",
		},
		"no search": {
			db:     driver,
			expErr: "search is nil",
		},
		"no genesis block hash": {
			db:     driver,
			search: &search.Search{},
			expErr: "genesis block hash is empty",
		},
		"success": {
			db:               driver,
			search:           &search.Search{},
			genesisBlockHash: genesisblockValid.Hash,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			blockchain, err := New(tt.db, tt.search, tt.genesisBlockHash)
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
	blockchain, err := New(driver, &search.Search{}, genesisblockValid.Hash)
	assert.NoError(t, err)
	// first run will be init
	err = blockchain.InitOrLoad(true)
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

	genesisByHeight, err := blockchain.GetBlockByNumber(0)
	assert.NoError(t, err)
	assert.Equal(t, *genBlock, *genesisByHeight)

	// blockchain already has the genesis block
	// add another block to the blockchain with a different verifier
	validBlock2, kp, _ := validBlock(t, 1)
	addrOfBlock2Verifier := kp.Address
	validBlock2.PreviousBlockHash = make([]byte, len(genBlock.Hash))
	copy(validBlock2.PreviousBlockHash, genBlock.Hash)

	err = validBlock2.Sign(kp.PrivateKey)
	assert.NoError(t, err)
	pubKeyBytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)
	block.SetBlockVerifiers(block.Verifier{
		Address:   kp.Address,
		PublicKey: hexutil.Encode(pubKeyBytes),
	})
	err = blockchain.PerformStateUpdateFromBlock(*validBlock2)
	assert.NoError(t, err)

	block2ByHeight, err := blockchain.GetBlockByNumber(1)
	assert.NoError(t, err)
	assert.EqualValues(t, validBlock2.Hash, block2ByHeight.Hash)

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
	block.SetBlockVerifiers(block.Verifier{
		Address:   kp.Address,
		PublicKey: hexutil.Encode(pubKeyBytes),
	})
	err = blockchain.PerformStateUpdateFromBlock(*validBlock3)

	assert.NoError(t, err)
	// perform another update with the same block should throw an error
	err = blockchain.PerformStateUpdateFromBlock(*validBlock3)
	assert.EqualError(t, err, "block is already within the blockchain")

	block3ByHeight, err := blockchain.GetBlockByNumber(2)
	assert.NoError(t, err)
	assert.EqualValues(t, validBlock3.Hash, block3ByHeight.Hash)

	// GetAddressTransactions and check pagination
	addressOfBlock2Verifier, _ := hexutil.Decode(addrOfBlock2Verifier)
	addressTransactions, blockNumbers, timestamps, err := blockchain.GetAddressTransactions(addressOfBlock2Verifier, 0, 1)
	assert.NoError(t, err)
	assert.Len(t, blockNumbers, 1)
	assert.Len(t, timestamps, 1)

	// both transactions are in the same block
	assert.Equal(t, uint64(1), blockNumbers[0])
	assert.Len(t, addressTransactions, 1)
	assert.EqualValues(t, validBlock2.Transactions[1].Hash, addressTransactions[0].Hash)

	addressTransactions, blockNumbers, timestamps, err = blockchain.GetAddressTransactions(addressOfBlock2Verifier, 1, 1)
	assert.NoError(t, err)
	assert.Len(t, blockNumbers, 1)
	assert.Len(t, timestamps, 1)
	// both transactions are in the same block
	assert.Equal(t, uint64(1), blockNumbers[0])
	assert.Len(t, addressTransactions, 1)
	assert.EqualValues(t, validBlock2.Transactions[0].Hash, addressTransactions[0].Hash)

	addressTransactions, blockNumbers, timestamps, err = blockchain.GetAddressTransactions(addressOfBlock2Verifier, 3, 1)
	assert.NoError(t, err)
	assert.Len(t, blockNumbers, 0)
	assert.Len(t, addressTransactions, 0)
	assert.Len(t, timestamps, 0)

	addressTransactions, blockNumbers, timestamps, err = blockchain.GetAddressTransactions(addressOfBlock2Verifier, 0, 10)
	assert.NoError(t, err)
	assert.Len(t, blockNumbers, 2)
	assert.Len(t, addressTransactions, 2)
	assert.Len(t, timestamps, 2)

	// GetTransactionByHash
	transactionsByHash, whichBlocksTheyBelongTo, err := blockchain.GetTransactionByHash(validBlock2.Transactions[1].Hash)
	assert.NoError(t, err)
	assert.Len(t, transactionsByHash, 1)
	assert.Len(t, whichBlocksTheyBelongTo, 1)
	assert.Equal(t, uint64(1), whichBlocksTheyBelongTo[0])
	assert.Equal(t, validBlock2.Transactions[1], transactionsByHash[0])

	lastUpdate := blockchain.GetLastBlockUpdatedAt()
	assert.True(t, time.Now().Unix()-lastUpdate < 5)

	// load and verify blockchain
	// height should be 2
	// last block hash should be validBlock3.Hash
	blockchain2, err := New(driver, &search.Search{}, genesisblockValid.Hash)
	assert.NoError(t, err)
	err = blockchain2.InitOrLoad(true)
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
	blockchain, err := New(driver, &search.Search{}, genesisblockValid.Hash)
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
	blockchain, err := New(driver, &search.Search{}, genesisblockValid.Hash)
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
	blockchain, err := New(driver, &search.Search{}, genesisblockValid.Hash)
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

func TestMemPoolBlockPoolMethods(t *testing.T) {
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

	blockchain, err := New(driver, &search.Search{}, genesisblockValid.Hash)
	assert.NoError(t, err)

	err = blockchain.InitOrLoad(true)
	assert.NoError(t, err)

	transactions := blockchain.GetTransactionsFromPool()
	assert.Len(t, transactions, 0)

	tx := transaction.Transaction{
		Hash:            []byte{10},
		Signature:       []byte{53},
		PublicKey:       []byte{40},
		Nounce:          []byte{1},
		Data:            []byte{20},
		From:            "0x01",
		To:              "0x02",
		Value:           "0x03",
		TransactionFees: "0x0",
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
	assert.Equal(t, uint64(1), nounce)

	err = blockchain.DeleteFromMemPool(tx)
	assert.NoError(t, err)

	transactions = blockchain.GetTransactionsFromPool()
	assert.Len(t, transactions, 0)

	validBlock, kp, _ := validBlock(t, 1)
	validBlock.PreviousBlockHash = make([]byte, len(genesisblockValid.Hash))
	copy(validBlock.PreviousBlockHash, genesisblockValid.Hash)

	err = validBlock.Sign(kp.PrivateKey)
	assert.NoError(t, err)
	pubKeyBytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)
	block.SetBlockVerifiers(block.Verifier{
		Address:   kp.Address,
		PublicKey: hexutil.Encode(pubKeyBytes),
	})

	blocks := blockchain.GetBlocksFromPool()
	assert.Len(t, blocks, 0)
	err = blockchain.PutBlockPool(*validBlock)
	assert.NoError(t, err)

	// at this stage blockchain was updated
	assert.Equal(t, uint64(1), blockchain.GetHeight())

	blocks = blockchain.GetBlocksFromPool()
	assert.Len(t, blocks, 0)

	// future block
	block := block.Block{
		Hash:              []byte{2, 3, 4},
		MerkleHash:        []byte{4, 3},
		Signature:         []byte{22},
		Timestamp:         time.Now().Unix(),
		Data:              []byte{3},
		PreviousBlockHash: genesisblockValid.Hash,
		Transactions:      []transaction.Transaction{tx},
		Number:            10,
	}

	err = blockchain.PutBlockPool(block)
	assert.NoError(t, err)

	blocks = blockchain.GetBlocksFromPool()
	assert.Len(t, blocks, 1)

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

func TestChannelFunctionality(t *testing.T) {
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)
	db, err := leveldb.OpenFile("channels.db", nil)
	assert.NoError(t, err)

	driver, err := database.New(db)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("channels.db")
	})

	blockchain, err := New(driver, &search.Search{}, genesisblockValid.Hash)
	assert.NoError(t, err)
	fromAddrString := "0xdd9a374e8dce9d656073ec153580301b7d2c3850"
	fromAddr, err := hexutil.Decode(fromAddrString)
	assert.NoError(t, err)
	fromAddrPosterString := "0xdd9a374e8dce9d656073ec153580301b7d2c1212"
	fromAddrPoster, err := hexutil.Decode(fromAddrPosterString)
	assert.NoError(t, err)
	fromAddrAdminString := "0xdd9a374e8dce9d656073ec153580301b7d2c3000"
	fromAddrAdmin, err := hexutil.Decode(fromAddrAdminString)
	assert.NoError(t, err)
	channelNode := NodeItem{
		Name:     "channel 1",
		NodeHash: []byte{23},
		NodeType: NodeItemType_CHANNEL,
		Owner:    fromAddr,
		Posters:  [][]byte{fromAddrPoster},
		Admins:   [][]byte{fromAddrAdmin},
	}
	// saveNode
	err = blockchain.saveNode(&channelNode)
	assert.NoError(t, err)

	// saveAsChannel
	err = blockchain.saveAsChannel(channelNode.NodeHash)
	assert.NoError(t, err)

	// GetNodeItem
	retrivedNode, err := blockchain.GetNodeItem(channelNode.NodeHash)
	assert.NoError(t, err)
	assert.Equal(t, channelNode.Name, retrivedNode.Name)

	// GetChannels
	channels, err := blockchain.GetChannels(10, 0)
	assert.NoError(t, err)
	assert.Equal(t, channelNode.Name, channels[0].Name)

	// GetChildNodeItems
	childNodes, err := blockchain.GetChildNodeItems(channelNode.NodeHash)
	assert.NoError(t, err)
	assert.Empty(t, childNodes)
	childNode := NodeItem{
		Name:       "sub channel",
		NodeHash:   []byte{33},
		ParentHash: channelNode.NodeHash,
	}
	err = blockchain.saveNode(&childNode)
	assert.NoError(t, err)

	// saveNodeAsChildNode
	err = blockchain.saveNodeAsChildNode(channelNode.NodeHash, childNode.NodeHash)
	assert.NoError(t, err)
	newChildNodes, err := blockchain.GetChildNodeItems(channelNode.NodeHash)
	assert.NoError(t, err)
	assert.Len(t, newChildNodes, 1)
	assert.Equal(t, childNode.Name, newChildNodes[0].Name)

	// GetParentNodeItem
	parentNode, err := blockchain.GetParentNodeItem(childNode.NodeHash)
	assert.NoError(t, err)
	assert.NotNil(t, parentNode)
	assert.Equal(t, channelNode.Name, parentNode.Name)

	childChildNode := NodeItem{
		Name:       "inside sub channel",
		NodeHash:   []byte{53},
		ParentHash: childNode.NodeHash,
		NodeType:   NodeItemType_ENTRY,
	}
	err = blockchain.saveNode(&childChildNode)
	assert.NoError(t, err)

	// saveNodeAsChildNode
	err = blockchain.saveNodeAsChildNode(childNode.NodeHash, childChildNode.NodeHash)
	assert.NoError(t, err)
	newChildChildNodes, err := blockchain.GetChildNodeItems(childNode.NodeHash)
	assert.NoError(t, err)
	assert.NotNil(t, newChildChildNodes)
	assert.Len(t, newChildChildNodes, 1)
	assert.Equal(t, childChildNode.Name, newChildChildNodes[0].Name)

	// GetRootNodeItem
	rootNode, err := blockchain.GetRootNodeItem(childChildNode.NodeHash)
	assert.NoError(t, err)
	assert.NotNil(t, rootNode)
	assert.Equal(t, channelNode.Name, rootNode.Name)

	// GetPermissionFromRootNode for owner
	owner, admin, poster := blockchain.GetPermissionFromRootNode(rootNode, fromAddr)
	assert.Equal(t, true, owner)
	assert.Equal(t, false, admin)
	assert.Equal(t, false, poster)

	// GetPermissionFromRootNode for poster
	owner, admin, poster = blockchain.GetPermissionFromRootNode(rootNode, fromAddrPoster)
	assert.Equal(t, false, owner)
	assert.Equal(t, false, admin)
	assert.Equal(t, true, poster)

	// GetPermissionFromRootNode for admin
	owner, admin, poster = blockchain.GetPermissionFromRootNode(rootNode, fromAddrAdmin)
	assert.Equal(t, false, owner)
	assert.Equal(t, true, admin)
	assert.Equal(t, false, poster)

	// GetChannelsCount
	assert.Equal(t, uint64(1), blockchain.GetChannelsCount())
}

func TestPerformStateUpdateFromDataPayload(t *testing.T) {
	genesisblockValid, err := block.GetGenesisBlock()
	assert.NoError(t, err)
	db, err := leveldb.OpenFile("txdatapayload.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	blv, err := search.NewBleveSearch("txdatapayloadSearch.db")
	assert.NoError(t, err)
	searchEngine, err := search.New(blv)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		searchEngine.Close()
		os.RemoveAll("txdatapayload.db")
		os.RemoveAll("txdatapayloadSearch.db")
	})

	blockchain, err := New(driver, searchEngine, genesisblockValid.Hash)
	assert.NoError(t, err)

	fromAddrString := "0xdd9a374e8dce9d656073ec153580301b7d2c3850"
	fromAddr, err := hexutil.Decode(fromAddrString)
	assert.NoError(t, err)
	mainChain, err := hexutil.Decode("0x01")
	assert.NoError(t, err)
	nodes := []*NodeItem{
		{
			Name:      "channel one",
			Owner:     fromAddr,
			Enabled:   true,
			NodeType:  NodeItemType_CHANNEL,
			Timestamp: time.Now().Unix(),
		},
	}
	txPayloadBytes := transactionWithChannelPayload(t, nodes)
	// create a payload with not enough balance for channel operations
	txWithChannelPayload := &transaction.Transaction{
		Nounce:          []byte{1},
		From:            fromAddrString,
		To:              fromAddrString,
		Data:            txPayloadBytes,
		Value:           "0x0",
		TransactionFees: "0x0",
		Chain:           mainChain,
	}
	err = blockchain.performStateUpdateFromDataPayload(txWithChannelPayload)
	assert.EqualError(t, err, "total cost of channel actions (400000000000000000000) are higher than the supplied transaction fee (0)")
	fees := currency.FFG().Mul(currency.FFG(), big.NewInt(ChannelCreationFeesFFG))
	txWithChannelPayload.TransactionFees = "0x" + fees.Text(16)
	err = blockchain.performStateUpdateFromDataPayload(txWithChannelPayload)
	assert.NoError(t, err)
	channels, err := blockchain.GetChannels(10, 0)
	assert.NoError(t, err)
	assert.Len(t, channels, 1)
	assert.Equal(t, "channel one", channels[0].Name)
	// creating the same channel again should be an error
	err = blockchain.performStateUpdateFromDataPayload(txWithChannelPayload)
	assert.EqualError(t, err, "failed to create channel node: node with this hash already exists in db 0x20148fb96726ef3ff2e0c6ee73458dda99f6c9b7914ee1aec918f8ac35e949d0")

	// create another node with subchannel and assert the error with the required fees
	nodes2 := []*NodeItem{
		{
			Name:       "sub channel under main channel",
			Owner:      fromAddr,
			Enabled:    true,
			NodeType:   NodeItemType_SUBCHANNEL,
			Timestamp:  time.Now().Unix(),
			ParentHash: channels[0].NodeHash,
		},
	}
	txPayloadBytes2 := transactionWithChannelPayload(t, nodes2)
	txWithChannelPayload2 := &transaction.Transaction{
		Nounce:          []byte{1},
		From:            fromAddrString,
		To:              fromAddrString,
		Data:            txPayloadBytes2,
		Value:           "0x0",
		TransactionFees: "0x0",
		Chain:           mainChain,
	}
	err = blockchain.performStateUpdateFromDataPayload(txWithChannelPayload2)
	assert.EqualError(t, err, "total cost of channel actions (100000000000000000) are higher than the supplied transaction fee (0)")
	txWithChannelPayload2.TransactionFees = "0x" + fees.Text(16)
	err = blockchain.performStateUpdateFromDataPayload(txWithChannelPayload2)
	assert.NoError(t, err)
	subchan, err := blockchain.GetChildNodeItems(channels[0].NodeHash)
	assert.NoError(t, err)
	assert.Len(t, subchan, 1)
	assert.Equal(t, "sub channel under main channel", subchan[0].Name)

	// create a channel and a subchannel and an entry in the subchannel all together in the same transaction
	channelHash := crypto.Sha256(bytes.Join(
		[][]byte{
			fromAddr,
			[]byte("channel FFG"),
		},
		[]byte{},
	))

	subchannelHash := crypto.Sha256(bytes.Join(
		[][]byte{
			channelHash,
			[]byte("subchannel of ffg"),
		},
		[]byte{},
	))

	folderUnderSubchannelHash := crypto.Sha256(bytes.Join(
		[][]byte{
			subchannelHash,
			[]byte("subchannel of ffg 2 folder"),
		},
		[]byte{},
	))

	nodes3 := []*NodeItem{
		{
			Name:        "channel FFG",
			Owner:       fromAddr,
			Enabled:     true,
			NodeType:    NodeItemType_CHANNEL,
			Timestamp:   time.Now().Unix(),
			Description: proto.String("hello world this is ffg"),
		},
		{
			Name:        "subchannel of ffg",
			ParentHash:  channelHash,
			Owner:       fromAddr,
			Enabled:     true,
			NodeType:    NodeItemType_SUBCHANNEL,
			Timestamp:   time.Now().Unix(),
			Description: proto.String("this is ffgs sub channel"),
		},
		{
			Name:        "subchannel of ffg 2 folder",
			ParentHash:  subchannelHash,
			Owner:       fromAddr,
			Enabled:     true,
			NodeType:    NodeItemType_DIR,
			Timestamp:   time.Now().Unix(),
			Description: proto.String("another folder"),
		},
		{
			Name:        "this is a file under subchannel",
			ParentHash:  folderUnderSubchannelHash,
			Owner:       fromAddr,
			Enabled:     true,
			NodeType:    NodeItemType_FILE,
			FileHash:    []byte{9},
			Size:        proto.Uint64(1024),
			Timestamp:   time.Now().Unix(),
			Description: proto.String("welcome to ffg"),
		},
	}

	txPayloadBytes3 := transactionWithChannelPayload(t, nodes3)
	txWithChannelPayload3 := &transaction.Transaction{
		Nounce:          []byte{1},
		From:            fromAddrString,
		To:              fromAddrString,
		Data:            txPayloadBytes3,
		Value:           "0x0",
		TransactionFees: "0x" + fees.Mul(fees, big.NewInt(4)).Text(16),
		Chain:           mainChain,
	}
	err = blockchain.performStateUpdateFromDataPayload(txWithChannelPayload3)
	assert.NoError(t, err)

	allChannels, err := blockchain.GetChannels(10, 0)
	assert.NoError(t, err)
	assert.Len(t, allChannels, 2)

	secondSubChannelChilds, err := blockchain.GetChildNodeItems(allChannels[0].NodeHash)
	assert.NoError(t, err)
	assert.Len(t, secondSubChannelChilds, 1)
	assert.Equal(t, "subchannel of ffg", secondSubChannelChilds[0].Name)

	childsOfSubchannelffg, err := blockchain.GetChildNodeItems(secondSubChannelChilds[0].NodeHash)
	assert.NoError(t, err)
	assert.Len(t, childsOfSubchannelffg, 1)
	assert.Equal(t, "subchannel of ffg 2 folder", childsOfSubchannelffg[0].Name)

	files, err := blockchain.GetFilesFromEntryOrFolderRecursively(childsOfSubchannelffg[0].NodeHash)
	assert.NoError(t, err)
	assert.Len(t, files, 1)
	assert.Equal(t, "this is a file under subchannel", files[0].Name)
	assert.Equal(t, "subchannel of ffg 2 folder/this is a file under subchannel", files[0].Path)
	assert.Equal(t, uint64(1024), files[0].Size)

	fileItem, err := blockchain.GetNodeFileItemFromFileHash([]byte{9})
	assert.NoError(t, err)
	assert.Len(t, fileItem, 1)
	assert.Equal(t, NodeItemType_FILE, fileItem[0].NodeType)
	assert.Equal(t, proto.Uint64(1024), fileItem[0].Size)

	// check limit and offset
	allChannels, err = blockchain.GetChannels(1, 0)
	assert.NoError(t, err)
	assert.Len(t, allChannels, 1)
	assert.Equal(t, "channel FFG", allChannels[0].Name)

	allChannels, err = blockchain.GetChannels(1, 1)
	assert.NoError(t, err)
	assert.Len(t, allChannels, 1)
	assert.Equal(t, "channel one", allChannels[0].Name)

	// offset bigger than the
	allChannels, err = blockchain.GetChannels(1, 2)
	assert.NoError(t, err)
	assert.Len(t, allChannels, 0)

	// check the search engine
	searchResults, err := searchEngine.Search(context.TODO(), "file", 100, 0, search.AnyTermRequired)
	assert.NoError(t, err)
	assert.Len(t, searchResults, 1)
	assert.Equal(t, uint64(2), blockchain.GetChannelsCount())

	// transaction with download contract payload
	txPayloadBytes4 := transactionWithContractPayload(t)
	txWithContractPayload := &transaction.Transaction{
		Hash:            []byte{2, 4},
		Nounce:          []byte{1},
		From:            fromAddrString,
		To:              fromAddrString,
		Data:            txPayloadBytes4,
		Value:           "0x0",
		TransactionFees: "0x" + fees.Mul(fees, big.NewInt(4)).Text(16),
		Chain:           mainChain,
	}
	err = blockchain.performStateUpdateFromDataPayload(txWithContractPayload)
	assert.NoError(t, err)

	contractMetadata, err := blockchain.GetDownloadContractInTransactionDataTransactionHash([]byte{23})
	assert.NoError(t, err)
	assert.Len(t, contractMetadata, 1)
	assert.Equal(t, []byte{2, 4}, contractMetadata[0].TxHash)
	assert.Equal(t, []byte{23}, contractMetadata[0].DownloadContractInTransactionDataProto.ContractHash)
	assert.Equal(t, []byte{2}, contractMetadata[0].DownloadContractInTransactionDataProto.FileRequesterNodePublicKey)
	assert.Equal(t, []byte{3}, contractMetadata[0].DownloadContractInTransactionDataProto.FileHosterNodePublicKey)
	assert.Equal(t, []byte{4}, contractMetadata[0].DownloadContractInTransactionDataProto.VerifierPublicKey)
	assert.Equal(t, "0x1", contractMetadata[0].DownloadContractInTransactionDataProto.VerifierFees)
	assert.Equal(t, "0x5", contractMetadata[0].DownloadContractInTransactionDataProto.FileHosterFees)
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
	blockchain, err := New(driver, &search.Search{}, genesisblockValid.Hash)
	assert.NoError(t, err)
	validBlock, kp, kp2 := validBlock(t, 0)
	err = validBlock.Sign(kp.PrivateKey)
	assert.NoError(t, err)

	verifierAddr, err := hexutil.Decode(kp.Address)
	assert.NoError(t, err)

	// update the list of verifiers
	pubKeyBytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)
	block.SetBlockVerifiers(block.Verifier{
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

func transactionWithChannelPayload(t *testing.T, nodes []*NodeItem) []byte {
	items := NodeItems{
		Nodes: nodes,
	}
	itemsBytes, err := proto.Marshal(&items)
	assert.NoError(t, err)
	txPayload := transaction.DataPayload{
		Type:    transaction.DataType_CREATE_NODE,
		Payload: itemsBytes,
	}

	txPayloadBytes, err := proto.Marshal(&txPayload)
	assert.NoError(t, err)
	return txPayloadBytes
}

func transactionWithContractPayload(t *testing.T) []byte {
	dc := messages.DownloadContractInTransactionDataProto{
		ContractHash:               []byte{23},
		FileRequesterNodePublicKey: []byte{2},
		FileHosterNodePublicKey:    []byte{3},
		VerifierPublicKey:          []byte{4},
		VerifierFees:               "0x1",
		FileHosterFees:             "0x5",
	}

	contractsEnvelope := &messages.DownloadContractsHashesProto{
		Contracts: []*messages.DownloadContractInTransactionDataProto{&dc},
	}

	itemsBytes, err := proto.Marshal(contractsEnvelope)
	assert.NoError(t, err)
	txPayload := transaction.DataPayload{
		Type:    transaction.DataType_DATA_CONTRACT,
		Payload: itemsBytes,
	}

	txPayloadBytes, err := proto.Marshal(&txPayload)
	assert.NoError(t, err)
	return txPayloadBytes
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
