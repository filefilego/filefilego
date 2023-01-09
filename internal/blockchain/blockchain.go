package blockchain

import (
	"errors"
	"fmt"
	sync "sync"

	"github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/filefilego/filefilego/internal/database"
	"github.com/filefilego/filefilego/internal/transaction"
)

// Blockchain represents a blockchain.
// type Blockchain interface {
// 	AddHeight(h uint64)
// 	GetHeight() uint64

// 	// we need boltdb bucket for hash->tx
// 	GetTransactionByHash(hash string) (tx transaction.Transaction, block block.Block, index uint64, err error)
// 	// we need a boltdb bucket for addr->txhash
// 	GetTransactionsByAddress(address string) (txs []transaction.Transaction, err error)
// 	// we need a bucket for height->block
// 	GetBlockByHeight(number uint64) (block block.Block, err error)
// 	// this will be fixed if we implement the above
// 	GetBlocksByRange(from uint64, to uint64) ([]block.Block, error)
// 	// we need a bucket for hash->blockchain
// 	GetBlockByHash(hash string) (block block.Block, err error)

// 	AddBalanceTo(address string, amount *big.Int) error
// 	SubBalanceOf(address string, amount *big.Int, nounce string) error

// 	MutateChannel(t transaction.Transaction, vbalances map[string]*big.Int, isMiningMode bool) error
// 	MutateAddressStateFromTransaction(transaction transaction.Transaction, isCoinbase bool) (err error)
// 	HasThisBalance(address string, amount *big.Int) (bool, *big.Int, *big.Int, error)

// 	// already hanled by transaction package
// 	SignTransaction(transaction transaction.Transaction, keystroe string) (transaction.Transaction, error)
// 	IsValidTransaction(transaction transaction.Transaction) (bool, error)

// 	GetNounceFromMemPool(address string) (string, error)

// 	AddBlockPool(block block.Block) (bool, error)
// 	removeBlockPool(block block.Block) error
// 	ClearBlockPool(lock bool)

// 	AddMemPool(transaction transaction.Transaction) error
// 	RemoveMemPool(transaction transaction.Transaction) error

// 	// below one calls the other
// 	PersistMemPoolToDB() error
// 	SerializeMemPool() ([]byte, error)

// 	LoadToMemPoolFromDB()

// 	MineBlock(transactions []transaction.Transaction) (block.Block, error)
// 	// GetAddressData(address string) (ads AddressState, merr AddressDataResult)
// 	// TraverseChanNodes(hash []byte, fn transformNode)
// 	TraverseChain(fn transform)
// 	PreparePoolBlocksForMining() ([]transaction.Transaction, map[string]*big.Int)
// 	CalculateReward() string
// 	MineScheduler()
// }

// type transform func(block.Block)
// type transformNode func(ChanNode)
// type AddressDataResult int

const addressPrefix = "address"

// InterfaceBlockchain wraps the functionality of a blockchain.
type InterfaceBlockchain interface {
	GetBlocksFromPool() []block.Block
	PutBlockPool(block block.Block) error
	DeleteFromBlockPool(block block.Block) error
	PutMemPool(tx transaction.Transaction) error
	DeleteFromMemPool(tx transaction.Transaction) error
	GetTransactionsFromPool() []transaction.Transaction
	SaveBlockInDB(blck block.Block) error
	GetBlockByHash(blockHash []byte) (block.Block, error)
	GetAddressState(address []byte) (AddressState, error)
	UpdateAddressState(address []byte, state AddressState) error
	CloseDB() error
	IncrementHeightBy(h uint64)
	GetHeight() uint64
}

// Blockchain represents a blockchain structure.
type Blockchain struct {
	db        database.Database
	blockPool map[string]block.Block
	bmu       sync.RWMutex

	memPool map[string]transaction.Transaction
	tmu     sync.RWMutex

	height uint64
	hmu    sync.RWMutex
}

// New creates a new blockchain instance.
func New(db database.Database) (*Blockchain, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}
	return &Blockchain{
		db:        db,
		blockPool: make(map[string]block.Block),
		memPool:   make(map[string]transaction.Transaction),
	}, nil
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

// PutBlockPool adds a block to blockPool.
func (b *Blockchain) PutBlockPool(block block.Block) error {
	b.bmu.Lock()
	defer b.bmu.Unlock()

	blockHash := hexutil.Encode(block.Hash)
	b.blockPool[blockHash] = block
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

// PutMemPool adds a transaction to mempool.
func (b *Blockchain) PutMemPool(tx transaction.Transaction) error {
	b.tmu.Lock()
	defer b.tmu.Unlock()

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
	err = b.db.Put(blck.Hash, data)
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

	blockData, err := b.db.Get(blockHash)
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
