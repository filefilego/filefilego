package blockchain

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	sync "sync"
	"time"

	"github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/common/currency"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/filefilego/filefilego/internal/crypto"
	"github.com/filefilego/filefilego/internal/database"
	"github.com/filefilego/filefilego/internal/node/protocols/messages"
	"github.com/filefilego/filefilego/internal/search"
	"github.com/filefilego/filefilego/internal/transaction"
	log "github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"google.golang.org/protobuf/proto"
)

const (
	addressPrefix            = "ad"
	blockPrefix              = "bl"
	lastBlockPrefix          = "last_block"
	blockNumberPrefix        = "bn"
	addressTransactionPrefix = "atx"
	transactionPrefix        = "tx"
	nodePrefix               = "nd"
	contractPrefix           = "co"
	nodeNodesPrefix          = "nn"
	channelPrefix            = "ch"
	channelsCountPrefix      = "channels_count"

	channelCreationFeesFFG               = 20000
	remainingChannelOperationFeesMiliFFG = 50
)

// Interface wraps the functionality of a blockchain.
type Interface interface {
	GetBlocksFromPool() []block.Block
	PutBlockPool(block block.Block) error
	DeleteFromBlockPool(block block.Block) error
	PutMemPool(tx transaction.Transaction) error
	DeleteFromMemPool(tx transaction.Transaction) error
	GetTransactionsFromPool() []transaction.Transaction
	SaveBlockInDB(blck block.Block) error
	GetBlockByHash(blockHash []byte) (block.Block, error)
	GetNounceFromMemPool(address []byte) uint64
	GetAddressState(address []byte) (AddressState, error)
	UpdateAddressState(address []byte, state AddressState) error
	CloseDB() error
	IncrementHeightBy(h uint64)
	GetHeight() uint64
	GetLastBlockHash() []byte
	PerformStateUpdateFromBlock(validBlock block.Block) error
	GetBlockByNumber(blockNumber uint64) (*block.Block, error)
	GetLastBlockUpdatedAt() int64
	GetTransactionByHash(hash []byte) ([]transaction.Transaction, []uint64, error)
	GetAddressTransactions(address []byte) ([]transaction.Transaction, []uint64, error)
	GetChannels(limit, offset int) ([]*NodeItem, error)
	GetChannelsCount() uint64
	GetChildNodeItems(nodeHash []byte) ([]*NodeItem, error)
	GetNodeItem(nodeHash []byte) (*NodeItem, error)
	GetParentNodeItem(nodeHash []byte) (*NodeItem, error)
	GetDownloadContractInTransactionDataTransactionHash(contractHash []byte) ([]DownloadContractInTransactionDataTxHash, error)
}

// Blockchain represents a blockchain structure.
type Blockchain struct {
	db        database.Database
	search    search.IndexSearcher
	blockPool map[string]block.Block
	bmu       sync.RWMutex

	memPool map[string]transaction.Transaction
	tmu     sync.RWMutex

	height uint64
	hmu    sync.RWMutex

	genesisBlockHash           []byte
	updatingBlockchainStateMux sync.RWMutex
	updatingBlockchainState    bool
	// lastBlockUpdateAt used to trigger syncing
	lastBlockUpdateAt int64
	lastBlockUpdateMu sync.RWMutex
}

// New creates a new blockchain instance.
func New(db database.Database, search search.IndexSearcher, genesisBlockHash []byte) (*Blockchain, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	if search == nil {
		return nil, errors.New("search is nil")
	}

	if len(genesisBlockHash) == 0 {
		return nil, errors.New("genesis block hash is empty")
	}

	b := &Blockchain{
		db:               db,
		search:           search,
		blockPool:        make(map[string]block.Block),
		memPool:          make(map[string]transaction.Transaction),
		genesisBlockHash: make([]byte, len(genesisBlockHash)),
	}

	copy(b.genesisBlockHash, genesisBlockHash)

	return b, nil
}

// InitOrLoad intializes or loads the blockchain from the database.
func (b *Blockchain) InitOrLoad() error {
	// reset height
	b.SetHeight(0)

	lastBlockHash := b.GetLastBlockHash()
	if len(lastBlockHash) == 0 {
		// init blockchain
		genesisBlock, err := block.GetGenesisBlock()
		if err != nil {
			return fmt.Errorf("failed to get genesis block: %w", err)
		}

		log.Info("genesis block hash: ", hexutil.Encode(genesisBlock.Hash))
		err = b.PerformStateUpdateFromBlock(*genesisBlock)
		if err != nil {
			return fmt.Errorf("failed to perform block state update: %w", err)
		}
		return nil
	}

	// load blockchain and verify
	for {
		foundBlock, err := b.GetBlockByHash(lastBlockHash)
		if err != nil {
			return fmt.Errorf("failed to get block: %v with error: %w", hexutil.Encode(lastBlockHash), err)
		}
		ok, err := foundBlock.Validate()
		if err != nil || !ok {
			return fmt.Errorf("failed to verify block: %s : %w", hexutil.Encode(lastBlockHash), err)
		}

		lastBlockHash = make([]byte, len(foundBlock.PreviousBlockHash))
		copy(lastBlockHash, foundBlock.PreviousBlockHash)

		// if we reach the genesis block
		if bytes.Equal(lastBlockHash, []byte{0}) {
			break
		}
		b.IncrementHeightBy(1)
	}

	return nil
}

// GetLastBlockUpdatedAt returns the timestamp of the last blockchain update from a block.
func (b *Blockchain) GetLastBlockUpdatedAt() int64 {
	b.lastBlockUpdateMu.RLock()
	defer b.lastBlockUpdateMu.RUnlock()

	return b.lastBlockUpdateAt
}

// SetHeight sets the height of the blockchain.
func (b *Blockchain) SetHeight(h uint64) {
	b.hmu.Lock()
	defer b.hmu.Unlock()

	b.height = h
}

// SetLastBlockHash sets the last block hash.
func (b *Blockchain) SetLastBlockHash(data []byte) error {
	if err := b.db.Put([]byte(lastBlockPrefix), data); err != nil {
		return fmt.Errorf("failed to update last block hash in db: %w", err)
	}
	return nil
}

// GetLastBlockHash gets the last block hash.
func (b *Blockchain) GetLastBlockHash() []byte {
	data, err := b.db.Get([]byte(lastBlockPrefix))
	if err != nil || len(data) == 0 {
		return nil
	}
	return data
}

// IncrementHeightBy increments the blockchain height by the given number.
func (b *Blockchain) IncrementHeightBy(h uint64) {
	b.hmu.Lock()
	defer b.hmu.Unlock()

	b.height += h
}

// GetHeight gets the height of the blockchain.
func (b *Blockchain) GetHeight() uint64 {
	b.hmu.RLock()
	defer b.hmu.RUnlock()

	return b.height
}

// GetBlocksFromPool get all the block from blockpool.
func (b *Blockchain) GetBlocksFromPool() []block.Block {
	b.bmu.RLock()
	defer b.bmu.RUnlock()

	blocks := make([]block.Block, 0, len(b.blockPool))
	for _, blc := range b.blockPool {
		blocks = append(blocks, blc)
	}

	return blocks
}

// indexBlockHashByBlockNumber indexes the blockHash by the block number so we can query db by block numbers.
func (b *Blockchain) indexBlockHashByBlockNumber(blockHash []byte, blockNumber uint64) error {
	blockNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumberBytes, blockNumber)

	if err := b.db.Put(append([]byte(blockNumberPrefix), blockNumberBytes...), blockHash); err != nil {
		return fmt.Errorf("failed to save block number and hash into db: %w", err)
	}
	return nil
}

// indexBlockTransactions indexes the transactions of blocks so they can be retrieved by hash.
// block number is included in the key and the value is an empty byte.
// use an iterator to find the transaction hashes, in this way its possible to index coinbase txs.
func (b *Blockchain) indexBlockTransactions(validBlock block.Block) error {
	blockNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumberBytes, validBlock.Number)
	batch := new(leveldb.Batch)
	for _, v := range validBlock.Transactions {
		prefixWithTransactionHash := append([]byte(transactionPrefix), v.Hash...)
		batch.Put(append(prefixWithTransactionHash, blockNumberBytes...), []byte{})
	}
	err := b.db.Write(batch, nil)
	if err != nil {
		return fmt.Errorf("failed to write batch of block transactions: %w", err)
	}

	return nil
}

// GetTransactionByHash returns a list of transactions found in db.
func (b *Blockchain) GetTransactionByHash(hash []byte) ([]transaction.Transaction, []uint64, error) {
	prefixWithTransacton := append([]byte(transactionPrefix), hash...)
	iter := b.db.NewIterator(util.BytesPrefix(prefixWithTransacton), nil)

	blockNumbers := make([]uint64, 0)

	for iter.Next() {
		key := iter.Key()
		blockNumberBytes := key[len(prefixWithTransacton):]
		blockNumbers = append(blockNumbers, binary.BigEndian.Uint64(blockNumberBytes))
	}
	iter.Release()
	err := iter.Error()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to release transaction by hash iterator: %w", err)
	}

	// get the blocks
	transactions := make([]transaction.Transaction, 0)
	for _, blckNum := range blockNumbers {
		block, err := b.GetBlockByNumber(blckNum)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get block %d : %w", blckNum, err)
		}

		for _, tx := range block.Transactions {
			if bytes.Equal(hash, tx.Hash) {
				transactions = append(transactions, tx)
			}
		}
	}

	if len(transactions) != len(blockNumbers) {
		return nil, nil, errors.New("transactions list length is not equal to block numbers length")
	}

	return transactions, blockNumbers, nil
}

// indexTransactionsByAddress indexes the transaction by the addresses "from" and "to".
// indexing is based on the following key: prefix_address_blocknumber_transactionIndex
func (b *Blockchain) indexTransactionsByAddresses(validBlock block.Block) error {
	blockNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumberBytes, validBlock.Number)

	batch := new(leveldb.Batch)
	for i, v := range validBlock.Transactions {
		indexBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(indexBytes, uint64(i))

		fromAddr, _ := hexutil.Decode(v.From)
		toAddr, _ := hexutil.Decode(v.To)

		prefixWithFromAddress := append([]byte(addressTransactionPrefix), fromAddr...)
		prefixWithToAddress := append([]byte(addressTransactionPrefix), toAddr...)

		// nolint:gocritic
		prefixWithFromAddressBlocknumber := append(prefixWithFromAddress, blockNumberBytes...)
		// nolint:gocritic
		prefixWithToAddressBlocknumber := append(prefixWithToAddress, blockNumberBytes...)

		batch.Put(append(prefixWithFromAddressBlocknumber, indexBytes...), v.Hash)
		batch.Put(append(prefixWithToAddressBlocknumber, indexBytes...), v.Hash)
	}
	err := b.db.Write(batch, nil)
	if err != nil {
		return fmt.Errorf("failed to write batch of address and transactions: %w", err)
	}

	return nil
}

// GetAddressTransactions returns a list of transaction given the address.
func (b *Blockchain) GetAddressTransactions(address []byte) ([]transaction.Transaction, []uint64, error) {
	prefixWithAddress := append([]byte(addressTransactionPrefix), address...)
	iter := b.db.NewIterator(util.BytesPrefix(prefixWithAddress), nil)

	blockNumbers := make([]uint64, 0)
	txIndexes := make([]int64, 0)
	// txHashes := make([][]byte, 0)

	for iter.Next() {
		key := iter.Key()

		blockNumAndTxIndex := key[len(prefixWithAddress):]

		blockNumbers = append(blockNumbers, binary.BigEndian.Uint64(blockNumAndTxIndex[:8]))
		txIndexes = append(txIndexes, int64(binary.BigEndian.Uint64(blockNumAndTxIndex[8:])))
		tmpVal := make([]byte, len(iter.Value()))
		copy(tmpVal, iter.Value())
		// txHashes = append(txHashes, tmpVal)
	}
	iter.Release()
	err := iter.Error()
	if err != nil {
		return nil, nil, fmt.Errorf("iterator error while getting transactions: %w", err)
	}

	transactions := make([]transaction.Transaction, len(txIndexes))

	for i, blockNum := range blockNumbers {
		validBlock, err := b.GetBlockByNumber(blockNum)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get block number %d in get transactions by address: %w", blockNum, err)
		}

		transactions[i] = validBlock.Transactions[txIndexes[i]]
	}

	return transactions, blockNumbers, nil
}

// GetBlockByNumber returns a block by number.
func (b *Blockchain) GetBlockByNumber(blockNumber uint64) (*block.Block, error) {
	blockNumberBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumberBytes, blockNumber)
	blockHash, err := b.db.Get(append([]byte(blockNumberPrefix), blockNumberBytes...))
	if err != nil {
		return nil, fmt.Errorf("failed to get block hash by block number: %w", err)
	}
	foundBlock, err := b.GetBlockByHash(blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get block by hash: %w", err)
	}
	return &foundBlock, nil
}

func (b *Blockchain) setUpdatingBlockchainState(updating bool) {
	b.updatingBlockchainStateMux.Lock()
	defer b.updatingBlockchainStateMux.Unlock()

	b.updatingBlockchainState = updating
}

func (b *Blockchain) getUpdatingBlockchainState() bool {
	b.updatingBlockchainStateMux.Lock()
	defer b.updatingBlockchainStateMux.Unlock()

	return b.updatingBlockchainState
}

// PutBlockPool adds a block to blockPool.
func (b *Blockchain) PutBlockPool(block block.Block) error {
	currentHeight := b.GetHeight()
	if block.Number < currentHeight {
		return nil
	}
	b.bmu.Lock()
	blockHash := hexutil.Encode(block.Hash)
	b.blockPool[blockHash] = block
	b.bmu.Unlock()

	// make other goroutines to return while update operation is being performed.
	if b.getUpdatingBlockchainState() {
		return nil
	}

	b.setUpdatingBlockchainState(true)
	defer b.setUpdatingBlockchainState(false)
	for {
		nextBlockFound := false
		lastBlockHash := b.GetLastBlockHash()
		if lastBlockHash == nil {
			return errors.New("last block hash is nil")
		}

		blocskPool := b.GetBlocksFromPool()
		for _, blck := range blocskPool {
			// remove old blocks from pool
			if blck.Number < currentHeight {
				if err := b.DeleteFromBlockPool(blck); err != nil {
					log.Errorf("failed to delete block %s from blockpool: %s", hexutil.Encode(blck.Hash), err.Error())
				}
				continue
			}

			if bytes.Equal(blck.PreviousBlockHash, lastBlockHash) {
				nextBlockFound = true
				if err := b.PerformStateUpdateFromBlock(blck); err != nil {
					log.Errorf("failed to perform blockchain update from block %s : %s", hexutil.Encode(blck.Hash), err.Error())
				}

				if err := b.DeleteFromBlockPool(blck); err != nil {
					log.Errorf("failed to delete block %s from blockpool: %s", hexutil.Encode(blck.Hash), err.Error())
				}
			}
		}

		if !nextBlockFound {
			break
		}
	}

	return nil
}

// DeleteFromBlockPool deletes a block from mempool.
func (b *Blockchain) DeleteFromBlockPool(block block.Block) error {
	b.bmu.Lock()
	defer b.bmu.Unlock()

	blockHash := hexutil.Encode(block.Hash)
	delete(b.blockPool, blockHash)
	return nil
}

// addBalanceTo adds balance to address.
func (b *Blockchain) addBalanceTo(address []byte, amount *big.Int) error {
	zeroBig := big.NewInt(0)
	if amount.Cmp(zeroBig) == -1 {
		return errors.New("amount is negative")
	}
	state, err := b.GetAddressState(address)
	// address has no balance
	if err != nil {
		state.SetBalance(big.NewInt(0))
		state.SetNounce(0)
	}

	balance, err := state.GetBalance()
	if err != nil {
		return fmt.Errorf("failed to get balance: %w", err)
	}

	state.SetBalance(balance.Add(balance, amount))

	err = b.UpdateAddressState(address, state)
	if err != nil {
		return fmt.Errorf("failed to update balance state: %w", err)
	}

	return nil
}

// subBalanceFrom subtracts balance from address.
func (b *Blockchain) subBalanceFrom(address []byte, amount *big.Int, nounce uint64) error {
	zeroBig := big.NewInt(0)
	if amount.Cmp(zeroBig) == -1 {
		return errors.New("amount is negative")
	}
	state, err := b.GetAddressState(address)
	// address has no balance
	if err != nil {
		return fmt.Errorf("address has no balance: %w", err)
	}

	balance, err := state.GetBalance()
	if err != nil {
		return fmt.Errorf("failed to get balance: %w", err)
	}

	if balance.Cmp(amount) < 0 {
		return errors.New("failed to subtract: amount is greater than balance")
	}

	state.SetBalance(balance.Sub(balance, amount))
	state.SetNounce(nounce)

	err = b.UpdateAddressState(address, state)
	if err != nil {
		return fmt.Errorf("failed to update balance state: %w", err)
	}

	return nil
}

// PerformAddressStateUpdate performs state update.
// This function should be able to rollback to previous state in case of failure.
// APPLYING OPERATIONS ON BIG INTS MODIFIES THE UNDERLYING DATA.
func (b *Blockchain) PerformAddressStateUpdate(transaction transaction.Transaction, verifierAddr []byte, isCoinbase bool) error {
	ok, err := transaction.Validate()
	if err != nil || !ok {
		return fmt.Errorf("failed to validate transaction: %w", err)
	}
	txFees, err := hexutil.DecodeBig(transaction.TransactionFees)
	if err != nil {
		return fmt.Errorf("failed to decode transaction fees: %w", err)
	}

	fromAddrBytes, err := hexutil.Decode(transaction.From)
	if err != nil {
		return fmt.Errorf("failed to decode from address: %w", err)
	}

	fromState, err := b.GetAddressState(fromAddrBytes)
	if err != nil {
		// if from is not available, create a zero state
		fromState.SetNounce(0)
		fromState.SetBalance(big.NewInt(0))
		if err := b.UpdateAddressState(fromAddrBytes, fromState); err != nil {
			return fmt.Errorf("failed to initialize zero state for `from` address: %w", err)
		}
	}

	fromAddressNounceDB, err := fromState.GetNounce()
	if err != nil {
		return fmt.Errorf("failed to get nounce of address state: %w", err)
	}

	// if not coinbase tx, then subtract the amount from the account
	if !isCoinbase {
		fromAddressNounceTX := hexutil.DecodeBigFromBytesToUint64(transaction.Nounce)
		if fromAddressNounceTX != fromAddressNounceDB+1 {
			return fmt.Errorf("the nounce %d in transaction is not the next nounce of database value: %d", fromAddressNounceTX, fromAddressNounceDB)
		}

		txValue, err := hexutil.DecodeBig(transaction.Value)
		if err != nil {
			return fmt.Errorf("failed to decode transaction value: %w", err)
		}
		totalFees := txValue.Add(txValue, txFees)

		err = b.subBalanceFrom(fromAddrBytes, totalFees, fromAddressNounceTX)
		if err != nil {
			return fmt.Errorf("failed to subtract total value from address: %w", err)
		}
	}

	toAddrBytes, err := hexutil.Decode(transaction.To)
	if err != nil {
		return fmt.Errorf("failed to decode to address: %w", err)
	}

	txValue, err := hexutil.DecodeBig(transaction.Value)
	if err != nil {
		return fmt.Errorf("failed to decode transaction value: %w", err)
	}

	err = b.addBalanceTo(toAddrBytes, txValue)
	if err != nil {
		return fmt.Errorf("failed to add amount to balance: %w", err)
	}

	err = b.addBalanceTo(verifierAddr, txFees)
	if err != nil {
		return fmt.Errorf("failed to add amount to verifier's balance: %w", err)
	}

	err = b.performStateUpdateFromDataPayload(&transaction)
	if err != nil {
		log.Errorf("failed to perform state update from tx data payload: %s", err.Error())
	}

	return nil
}

// performStateUpdateFromDataPayload performs updates from the transaction data.
// operations allowed are related to updating blockchain settings and channel operations.
// there could be arbitrary data in the transaction data field so trying to unmarshal first and
// if failed then just return without any error.
func (b *Blockchain) performStateUpdateFromDataPayload(tx *transaction.Transaction) error {
	dataPayload := transaction.DataPayload{}
	err := proto.Unmarshal(tx.Data, &dataPayload)
	if err != nil {
		return nil
	}

	if dataPayload.Type == transaction.DataType_DATA_CONTRACT {
		downloadContracts := messages.DownloadContractInTransactionDataProto{}
		err := proto.Unmarshal(dataPayload.Payload, &downloadContracts)
		if err != nil {
			return nil
		}

		err = b.saveContractFromTransactionDataPayload(&downloadContracts, tx.Hash)
		if err != nil {
			return fmt.Errorf("failed to save contract in db: %w", err)
		}
	}

	// support creating multiple nodes
	if dataPayload.Type == transaction.DataType_CREATE_NODE {
		nodesEnvelope := NodeItems{}
		err := proto.Unmarshal(dataPayload.Payload, &nodesEnvelope)
		if err != nil {
			return nil
		}

		txFees, err := hexutil.DecodeBig(tx.TransactionFees)
		if err != nil {
			return fmt.Errorf("failed to get the transaction fee value while updating tx data payload: %w", err)
		}

		totalActionsFees := calculateChannelActionsFees(nodesEnvelope.Nodes)
		if txFees.Cmp(totalActionsFees) == -1 {
			return fmt.Errorf("total cost of channel actions (%s) are higher than the supplied transaction fee (%s)", totalActionsFees.Text(10), txFees.Text(10))
		}

		for _, node := range nodesEnvelope.Nodes {
			node.Enabled = true
			fromBytes, _ := hexutil.Decode(tx.From)
			node.Owner = fromBytes

			if node.Timestamp <= 0 {
				return fmt.Errorf("timestamp is empty")
			}

			if node.NodeType == NodeItemType_CHANNEL {
				if node.Name == "" {
					return errors.New("channel node name is empty")
				}

				data := bytes.Join(
					[][]byte{
						fromBytes,
						[]byte(node.Name),
					},
					[]byte{},
				)
				node.ParentHash = []byte{}
				node.NodeHash = crypto.Sha256(data)

				err = b.saveNode(node)
				if err != nil {
					return fmt.Errorf("failed to create channel node: %w", err)
				}
				err = b.saveAsChannel(node.NodeHash)
				if err != nil {
					return fmt.Errorf("failed add to channel list: %w", err)
				}
			} else {
				if len(node.ParentHash) == 0 {
					return fmt.Errorf("parent hash of node is empty")
				}

				data := bytes.Join(
					[][]byte{
						node.ParentHash,
						[]byte(node.Name),
					},
					[]byte{},
				)

				node.NodeHash = crypto.Sha256(data)

				// get parent
				parentNode, err := b.GetNodeItem(node.ParentHash)
				if err != nil {
					return fmt.Errorf("failed to get parent of node %s : %w", hexutil.Encode(node.ParentHash), err)
				}

				// check if allowed to insert node to parent
				ok, err := applyChannelStructureConstraints(parentNode, node)
				if err != nil || !ok {
					return fmt.Errorf("failed to satisfy node structure constraints: %w", err)
				}

				var rootNodeItem *NodeItem
				// if parent is root
				if parentNode.NodeType == NodeItemType_CHANNEL {
					rootNodeItem = parentNode
				} else {
					// traverse back to find root
					rootItem, err := b.GetRootNodeItem(parentNode.NodeHash)
					if err != nil {
						return fmt.Errorf("failed to get root node item: %w", err)
					}
					rootNodeItem = rootItem
				}

				// get permissions to see if allowed
				owner, admin, poster := b.GetPermissionFromRootNode(rootNodeItem, fromBytes)
				if err != nil {
					return fmt.Errorf("failed to retreive root node to get permissions: %w", err)
				}

				if !owner && !admin && !poster && node.NodeType != NodeItemType_OTHER {
					return errors.New("only `other` nodes can be added by guest")
				}

				// if poster allow only to add entry, dir, file and other
				if poster && node.NodeType == NodeItemType_SUBCHANNEL {
					return errors.New("poster can't create channel and subchannel")
				}

				err = b.saveNode(node)
				if err != nil {
					return fmt.Errorf("failed to create node: %w", err)
				}
				err = b.saveNodeAsChildNode(parentNode.NodeHash, node.NodeHash)
				if err != nil {
					return fmt.Errorf("failed to save node child: %w", err)
				}
			}

			nodeDescription := ""
			if node.Description != nil {
				nodeDescription = *node.Description
			}

			indexItem := search.IndexItem{
				Hash:        hexutil.Encode(node.NodeHash),
				Type:        int32(node.NodeType),
				Name:        node.Name,
				Description: nodeDescription,
			}

			err = b.search.Index(indexItem)
			if err != nil {
				return fmt.Errorf("failed to index item into search engine: %w", err)
			}
		}
	}

	return nil
}

// PerformStateUpdateFromBlock performs updates from a block.
func (b *Blockchain) PerformStateUpdateFromBlock(validBlock block.Block) error {
	_, err := b.GetBlockByHash(validBlock.Hash)
	if err == nil {
		return errors.New("block is already within the blockchain")
	}

	// if the block is not genesis block then validate the previous block
	isGenesisBlock := bytes.Equal(b.genesisBlockHash, validBlock.Hash)
	if !isGenesisBlock {
		blockchainHeight := b.GetHeight()
		if validBlock.Number <= blockchainHeight {
			return fmt.Errorf("block: %d can't be smaller or equal to the blockchain height: %d", validBlock.Number, blockchainHeight)
		}

		previousBlock, err := b.GetBlockByHash(validBlock.PreviousBlockHash)
		if err != nil {
			return fmt.Errorf("previous block not found in database: %w", err)
		}

		if previousBlock.Number+1 != validBlock.Number {
			return fmt.Errorf("block number doesn't match the continuation of previous block: current: %d,  previous: %d", validBlock.Number, previousBlock.Number)
		}

		if validBlock.Timestamp < previousBlock.Timestamp {
			return fmt.Errorf("previous block timestamp %d is bigger than the current block %d", previousBlock.Timestamp, validBlock.Timestamp)
		}
	}

	coinbaseTx, err := validBlock.GetAndValidateCoinbaseTransaction()
	if err != nil {
		return fmt.Errorf("failed to get/validate coinbase transaction: %w", err)
	}

	verifierAddr, err := crypto.RawPublicToAddressBytes(coinbaseTx.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to get address of verifier: %w", err)
	}

	for _, tx := range validBlock.Transactions {
		isCoinbase, err := coinbaseTx.Equals(tx)
		if err != nil {
			return fmt.Errorf("failed to compare coinbase transaction: %w", err)
		}

		err = b.PerformAddressStateUpdate(tx, verifierAddr, isCoinbase)
		if err != nil {
			log.Errorf("failed to update the state of blockchain: %s", err.Error())
			_ = b.DeleteFromMemPool(tx)
			continue
		}

		if !isCoinbase {
			err = b.DeleteFromMemPool(tx)
			if err != nil {
				log.Warnf("failed to delete transaction from mempool: %s", err.Error())
			}
		}
	}

	if !isGenesisBlock {
		b.IncrementHeightBy(1)
	}

	err = b.SetLastBlockHash(validBlock.Hash)
	if err != nil {
		return fmt.Errorf("failed to update last block hash in db: %w", err)
	}

	err = b.SaveBlockInDB(validBlock)
	if err != nil {
		return fmt.Errorf("failed to save genesis block in DB: %w", err)
	}

	err = b.indexBlockHashByBlockNumber(validBlock.Hash, validBlock.Number)
	if err != nil {
		return fmt.Errorf("failed to index block hash by block number: %w", err)
	}

	err = b.indexTransactionsByAddresses(validBlock)
	if err != nil {
		return fmt.Errorf("failed to index transactions by address: %w", err)
	}

	err = b.indexBlockTransactions(validBlock)
	if err != nil {
		return fmt.Errorf("failed to index block transactions: %w", err)
	}

	b.lastBlockUpdateMu.Lock()
	b.lastBlockUpdateAt = time.Now().Unix()
	b.lastBlockUpdateMu.Unlock()

	return nil
}

// GetNounceFromMemPool get the nounce of an address from mempool.
func (b *Blockchain) GetNounceFromMemPool(address []byte) uint64 {
	b.tmu.RLock()
	defer b.tmu.RUnlock()

	tmp := uint64(0)
	for _, v := range b.memPool {
		if v.From == hexutil.Encode(address) {
			nounce := hexutil.DecodeBigFromBytesToUint64(v.Nounce)
			if nounce > tmp {
				tmp = nounce
			}
		}
	}
	return tmp
}

// PutMemPool adds a transaction to mempool.
// validation of transaction should be done outside this function.
func (b *Blockchain) PutMemPool(tx transaction.Transaction) error {
	b.tmu.Lock()
	defer b.tmu.Unlock()

	for idx, transaction := range b.memPool {
		// transaction is already in mempool with this nounce
		// pick the one with higher fee
		if bytes.Equal(transaction.Nounce, tx.Nounce) && transaction.From == tx.From {
			txFees, err := hexutil.DecodeBig(tx.TransactionFees)
			if err != nil {
				return fmt.Errorf("failed to decode transaction fees: %w", err)
			}
			txFeesInMempool, err := hexutil.DecodeBig(transaction.TransactionFees)
			if err != nil {
				return fmt.Errorf("failed to decode transaction fees from mempool: %w", err)
			}

			if txFees.Cmp(txFeesInMempool) == 1 {
				b.memPool[idx] = tx
				return nil
			}
		}
	}

	txHash := hexutil.Encode(tx.Hash)
	b.memPool[txHash] = tx
	return nil
}

// DeleteFromMemPool deletes a transaction from mempool.
func (b *Blockchain) DeleteFromMemPool(tx transaction.Transaction) error {
	b.tmu.Lock()
	defer b.tmu.Unlock()

	txHash := hexutil.Encode(tx.Hash)
	delete(b.memPool, txHash)
	return nil
}

// GetTransactionsFromPool get all the transactions from mempool.
func (b *Blockchain) GetTransactionsFromPool() []transaction.Transaction {
	b.tmu.RLock()
	defer b.tmu.RUnlock()

	txs := make([]transaction.Transaction, 0, len(b.memPool))
	for _, tx := range b.memPool {
		txs = append(txs, tx)
	}

	return txs
}

// SaveBlockInDB saves a block into the database.
func (b *Blockchain) SaveBlockInDB(blck block.Block) error {
	if len(blck.Hash) == 0 {
		return errors.New("blockhash is empty")
	}
	protoblock := block.ToProtoBlock(blck)
	data, err := block.MarshalProtoBlock(protoblock)
	if err != nil {
		return fmt.Errorf("failed to marshal protoblock: %w", err)
	}
	err = b.db.Put(append([]byte(blockPrefix), blck.Hash...), data)
	if err != nil {
		return fmt.Errorf("failed to save data into db: %w", err)
	}
	return nil
}

// GetBlockByHash gets a block by its hash.
func (b *Blockchain) GetBlockByHash(blockHash []byte) (block.Block, error) {
	if len(blockHash) == 0 {
		return block.Block{}, errors.New("blockhash is empty")
	}

	blockData, err := b.db.Get(append([]byte(blockPrefix), blockHash...))
	if err != nil {
		return block.Block{}, fmt.Errorf("failed to get block from database: %w", err)
	}

	protoBlock, err := block.UnmarshalProtoBlock(blockData)
	if err != nil {
		return block.Block{}, fmt.Errorf("failed to get unmarshal protoblock: %w", err)
	}

	return block.ProtoBlockToBlock(protoBlock), nil
}

// GetAddressState returns the state of the address from the db.
func (b *Blockchain) GetAddressState(address []byte) (AddressState, error) {
	data, err := b.db.Get(append([]byte(addressPrefix), address...))
	if err != nil {
		return AddressState{}, fmt.Errorf("failed to get address state: %w", err)
	}
	protoAddrState, err := UnmarshalAddressStateProto(data)
	if err != nil {
		return AddressState{}, fmt.Errorf("failed to unmarshal address state: %w", err)
	}
	return AddressStateProtoToAddressState(protoAddrState), nil
}

// UpdateAddressState updates the state of the address in the db.
func (b *Blockchain) UpdateAddressState(address []byte, state AddressState) error {
	if len(address) == 0 {
		return errors.New("address is empty")
	}

	protoAddrState := ToAddressStateProto(state)
	data, err := MarshalAddressStateProto(protoAddrState)
	if err != nil {
		return fmt.Errorf("failed to marshal address state: %w", err)
	}

	err = b.db.Put(append([]byte(addressPrefix), address...), data)
	if err != nil {
		return fmt.Errorf("failed to put to database: %w", err)
	}

	return nil
}

// CloseDB closes the db.
func (b *Blockchain) CloseDB() error {
	return b.db.Close()
}

// GetChannelsCount returns the count of total channels.
func (b *Blockchain) GetChannelsCount() uint64 {
	channelsCountBytes, err := b.db.Get([]byte(channelsCountPrefix))
	if err != nil {
		return 0
	}
	return binary.BigEndian.Uint64(channelsCountBytes)
}

func (b *Blockchain) saveAsChannel(nodeHash []byte) error {
	err := b.db.Put(append([]byte(channelPrefix), nodeHash...), []byte{})
	if err != nil {
		return fmt.Errorf("failed to insert node to channels: %w", err)
	}

	channelsCountBytes, err := b.db.Get([]byte(channelsCountPrefix))
	if err != nil || channelsCountBytes == nil {
		channelsUint64 := make([]byte, 8)
		binary.BigEndian.PutUint64(channelsUint64, 1)
		err := b.db.Put([]byte(channelsCountPrefix), channelsUint64)
		if err != nil {
			return fmt.Errorf("failed to insert to channels count: %w", err)
		}
		return nil
	}

	num := binary.BigEndian.Uint64(channelsCountBytes)
	num++
	channelsUint64 := make([]byte, 8)
	binary.BigEndian.PutUint64(channelsUint64, num)
	err = b.db.Put([]byte(channelsCountPrefix), channelsUint64)
	if err != nil {
		return fmt.Errorf("failed to update channels count: %w", err)
	}

	return nil
}

func (b *Blockchain) saveNode(node *NodeItem) error {
	nodeData, err := proto.Marshal(node)
	if err != nil {
		return fmt.Errorf("failed to marshal node item: %w", err)
	}
	_, err = b.GetNodeItem(node.NodeHash)
	if err == nil {
		return fmt.Errorf("node with this hash already exists in db %s", hexutil.Encode(node.NodeHash))
	}
	err = b.db.Put(append([]byte(nodePrefix), node.NodeHash...), nodeData)
	if err != nil {
		return fmt.Errorf("failed to insert node item into db: %w", err)
	}

	return nil
}

// DownloadContractInTransactionDataTxHash represents a contract metadata and a tx hash.
type DownloadContractInTransactionDataTxHash struct {
	TxHash                                 []byte
	DownloadContractInTransactionDataProto *messages.DownloadContractInTransactionDataProto
}

// GetDownloadContractInTransactionDataTransactionHash returns a list of contract data found in a transaction payload which are arrived in the node.
func (b *Blockchain) GetDownloadContractInTransactionDataTransactionHash(contractHash []byte) ([]DownloadContractInTransactionDataTxHash, error) {
	prefixWithContractHash := append([]byte(contractPrefix), contractHash...)
	iter := b.db.NewIterator(util.BytesPrefix(prefixWithContractHash), nil)
	contractData := make([]DownloadContractInTransactionDataTxHash, 0)
	for iter.Next() {
		key := iter.Key()
		txHash := key[len(prefixWithContractHash):]
		m := messages.DownloadContractInTransactionDataProto{}
		err := proto.Unmarshal(iter.Value(), &m)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal the download contract metadata: %w", err)
		}

		dc := DownloadContractInTransactionDataTxHash{
			TxHash:                                 make([]byte, len(txHash)),
			DownloadContractInTransactionDataProto: &m,
		}
		copy(dc.TxHash, txHash)

		contractData = append(contractData, dc)
	}
	iter.Release()
	err := iter.Error()
	if err != nil {
		return nil, fmt.Errorf("failed to release get download contract in transaction data iterator: %w", err)
	}

	return contractData, nil
}

// saveContractFromTransactionDataPayload saves a contract in the blockchain when a transaction is updating the blockchain state.
func (b *Blockchain) saveContractFromTransactionDataPayload(contractInfo *messages.DownloadContractInTransactionDataProto, txHash []byte) error {
	contactInfoBytes, err := proto.Marshal(contractInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal contract info: %w", err)
	}

	prefixWithContractHash := append([]byte(contractPrefix), contractInfo.ContractHash...)
	err = b.db.Put(append(prefixWithContractHash, txHash...), contactInfoBytes)
	if err != nil {
		return fmt.Errorf("failed to insert contract into db: %w", err)
	}

	return nil
}

func (b *Blockchain) saveNodeAsChildNode(parentHash, childHash []byte) error {
	prefixWithNodeNodes := append([]byte(nodeNodesPrefix), parentHash...)
	err := b.db.Put(append(prefixWithNodeNodes, childHash...), []byte{})
	if err != nil {
		return fmt.Errorf("failed to insert child node item under parent node: %w", err)
	}

	return nil
}

// GetChildNodeItems returns a list of child nodes of a node.
func (b *Blockchain) GetChildNodeItems(nodeHash []byte) ([]*NodeItem, error) {
	prefixWithNodeNodes := append([]byte(nodeNodesPrefix), nodeHash...)
	iter := b.db.NewIterator(util.BytesPrefix(prefixWithNodeNodes), nil)
	childNodes := make([]*NodeItem, 0)
	for iter.Next() {
		key := iter.Key()
		item, err := b.GetNodeItem(key[len(prefixWithNodeNodes):])
		if err != nil {
			continue
		}
		childNodes = append(childNodes, item)
	}
	iter.Release()
	err := iter.Error()
	if err != nil {
		return nil, fmt.Errorf("failed to release get child nodes iterator: %w", err)
	}

	return childNodes, nil
}

// GetChannels gets a list of channels.
func (b *Blockchain) GetChannels(limit, offset int) ([]*NodeItem, error) {
	iter := b.db.NewIterator(util.BytesPrefix([]byte(channelPrefix)), nil)
	channelNodes := make([]*NodeItem, 0)
	index := 0
	for iter.Next() {
		if limit == 0 {
			break
		}
		index++
		if index <= offset {
			continue
		}
		key := iter.Key()
		item, err := b.GetNodeItem(key[len([]byte(channelPrefix)):])
		if err != nil {
			continue
		}
		channelNodes = append(channelNodes, item)
		limit--
	}
	iter.Release()
	err := iter.Error()
	if err != nil {
		return nil, fmt.Errorf("failed to release get channels iterator: %w", err)
	}

	return channelNodes, nil
}

// GetNodeItem get a node.
func (b *Blockchain) GetNodeItem(nodeHash []byte) (*NodeItem, error) {
	nodeData, err := b.db.Get(append([]byte(nodePrefix), nodeHash...))
	if err != nil {
		return nil, fmt.Errorf("failed to get node item from database: %w", err)
	}
	cNode := NodeItem{}
	err = proto.Unmarshal(nodeData, &cNode)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal protobuf node item: %w", err)
	}
	return &cNode, nil
}

// GetParentNodeItem get a node.
func (b *Blockchain) GetParentNodeItem(nodeHash []byte) (*NodeItem, error) {
	nodeItem, err := b.GetNodeItem(nodeHash)
	if err != nil {
		return nil, fmt.Errorf("failed to find node: %w", err)
	}

	parentItem, err := b.GetNodeItem(nodeItem.ParentHash)
	if err != nil {
		return nil, fmt.Errorf("failed to find parent node: %w", err)
	}
	return parentItem, nil
}

// GetRootNodeItem traverse back until root node is reached and its a channel node.
func (b *Blockchain) GetRootNodeItem(nodeHash []byte) (*NodeItem, error) {
	var lastFoundNodeItem *NodeItem
	nodeHashToFind := make([]byte, len(nodeHash))
	copy(nodeHashToFind, nodeHash)
	for {
		nodeItem, err := b.GetParentNodeItem(nodeHashToFind)
		if err != nil {
			break
		}
		lastFoundNodeItem = nodeItem
		copy(nodeHashToFind, nodeItem.NodeHash)
	}

	if lastFoundNodeItem == nil || lastFoundNodeItem.NodeType != NodeItemType_CHANNEL {
		return nil, errors.New("failed to find root node")
	}
	return lastFoundNodeItem, nil
}

// GetPermissionFromRootNode get the permissions from channel node.
func (b *Blockchain) GetPermissionFromRootNode(rootNode *NodeItem, fromAddr []byte) (owner, admin, poster bool) {
	if bytes.Equal(rootNode.Owner, fromAddr) {
		owner = true
	}

	for _, v := range rootNode.Admins {
		if bytes.Equal(fromAddr, v) {
			admin = true
		}
	}

	for _, v := range rootNode.Posters {
		if bytes.Equal(fromAddr, v) {
			poster = true
		}
	}

	return owner, admin, poster
}

func applyChannelStructureConstraints(parentNode, node *NodeItem) (bool, error) {
	switch node.NodeType {
	case NodeItemType_SUBCHANNEL:
		{
			if !(parentNode.NodeType == NodeItemType_CHANNEL || parentNode.NodeType == NodeItemType_SUBCHANNEL) {
				return false, errors.New("subchannel is only allowed in a channel or a subchannel")
			}
		}

	case NodeItemType_ENTRY:
		{
			if !(parentNode.NodeType == NodeItemType_CHANNEL || parentNode.NodeType == NodeItemType_SUBCHANNEL) {
				return false, errors.New("entry is only allowed in a channel or a subchannel")
			}
		}
	case NodeItemType_DIR:
		fallthrough
	case NodeItemType_FILE:
		{
			if !(parentNode.NodeType == NodeItemType_CHANNEL || parentNode.NodeType == NodeItemType_SUBCHANNEL || parentNode.NodeType == NodeItemType_ENTRY || parentNode.NodeType == NodeItemType_DIR) {
				return false, errors.New("dir/file is only allowed in a channel, subchannel, dirs and entries")
			}
		}
	case NodeItemType_OTHER:
		{
			if parentNode.NodeType != NodeItemType_ENTRY {
				return false, errors.New("`other` node type is only allowed in an entry")
			}
		}
	default:
		return false, errors.New("unknown node type")
	}
	return true, nil
}

func calculateChannelActionsFees(nodes []*NodeItem) *big.Int {
	totalFees := big.NewInt(0)
	for _, n := range nodes {
		switch n.NodeType {
		case NodeItemType_CHANNEL:
			{
				oneFFG := currency.FFG()
				totalFees = totalFees.Add(totalFees, oneFFG.Mul(oneFFG, big.NewInt(channelCreationFeesFFG)))
			}
		default:
			{
				oneMiliFFG := currency.MiliFFG()
				totalFees = totalFees.Add(totalFees, oneMiliFFG.Mul(oneMiliFFG, big.NewInt(remainingChannelOperationFeesMiliFFG)))
			}
		}
	}

	return totalFees
}
