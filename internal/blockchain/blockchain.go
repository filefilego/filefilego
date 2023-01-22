package blockchain

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	sync "sync"

	"github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/filefilego/filefilego/internal/crypto"
	"github.com/filefilego/filefilego/internal/database"
	"github.com/filefilego/filefilego/internal/transaction"
	log "github.com/sirupsen/logrus"
)

const addressPrefix = "address"

const blockPrefix = "blocks"

const lastBlockPrefix = "last_block"

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

	genesisBlockHash []byte
}

// New creates a new blockchain instance.
func New(db database.Database, genesisBlockHash []byte) (*Blockchain, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	if len(genesisBlockHash) == 0 {
		return nil, errors.New("genesis block hash is empty")
	}

	b := &Blockchain{
		db:               db,
		blockPool:        make(map[string]block.Block),
		memPool:          make(map[string]transaction.Transaction),
		genesisBlockHash: make([]byte, len(genesisBlockHash)),
	}

	copy(b.genesisBlockHash, genesisBlockHash)

	return b, nil
}

// InitOrLoad increments the blockchain height by the given number.
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
			return fmt.Errorf("failed to verify block: %s", hexutil.Encode(lastBlockHash))
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

// SetHeight sets the height of the blockchain.
func (b *Blockchain) SetHeight(h uint64) {
	b.hmu.Lock()
	defer b.hmu.Unlock()

	b.height = h
}

// SetLastBlockHash sets the last block hash.
func (b *Blockchain) SetLastBlockHash(data []byte) error {
	err := b.db.Put([]byte(lastBlockPrefix), data)
	if err != nil {
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
		err := b.UpdateAddressState(fromAddrBytes, fromState)
		if err != nil {
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

	err = b.performStateUpdateFromDataPayload(transaction.Data)
	if err != nil {
		return fmt.Errorf("failed perform state update from transaction data: %w", err)
	}

	return nil
}

// performStateUpdateFromDataPayload performs updates from the transaction data.
// operations allowed are related to updating blockchain settings and channel operations.
func (b *Blockchain) performStateUpdateFromDataPayload(dataPayload []byte) error {
	// TODO
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

	err = b.DeleteFromBlockPool(validBlock)
	if err != nil {
		log.Warnf("failed to delete block %s from blockpool: %s", hexutil.Encode(validBlock.Hash), err.Error())
	}

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

	// TODO: handle the case when there is a tx with lower nounce than the one in db

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
