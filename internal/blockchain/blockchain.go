package blockchain

import (
	"errors"
	"log"

	"github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/database"
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

type Blockchain struct {
	db     database.Driver
	blocks []block.Block
}

func New(db database.Driver) (*Blockchain, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}
	return &Blockchain{
		db:     db,
		blocks: make([]block.Block, 0),
	}, nil
}

func (b *Blockchain) AddBlockToDB(blck block.Block) {
	protoblock := block.ToProtoBlock(blck)
	data, err := block.MarshalProtoBlock(protoblock)
	if err != nil {
		log.Fatal(err)
	}
	err = b.db.Put(blck.Hash, data)
	if err != nil {
		log.Fatal(err)
	}
}
