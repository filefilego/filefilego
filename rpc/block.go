package rpc

import (
	"errors"
	"net/http"

	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common/hexutil"
)

// BlockAPI represents the block rpc service.
type BlockAPI struct {
	blockchain blockchain.Interface
}

// NewBlockAPI creates a new block API to be served using JSONRPC.
func NewBlockAPI(bchain blockchain.Interface) (*BlockAPI, error) {
	if bchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	return &BlockAPI{
		blockchain: bchain,
	}, nil
}

// GetByNumberArgs represents the args of rpc request.
type GetByNumberArgs struct {
	Number uint64 `json:"number"`
}

// JSONBlock represents the block response of rpc request.
type JSONBlock struct {
	Number            uint64            `json:"number"`
	Timestamp         int64             `json:"timestamp"`
	Data              string            `json:"data"`
	PreviousBlockHash string            `json:"previous_block_hash"`
	Hash              string            `json:"hash"`
	Signature         string            `json:"signature"`
	MerkleHash        string            `json:"merkle_hash"`
	Transactions      []JSONTransaction `json:"transactions"`
}

// GetByNumber gets a block by number.
func (api *BlockAPI) GetByNumber(_ *http.Request, args *GetByNumberArgs, response *JSONBlock) error {
	validBlock, err := api.blockchain.GetBlockByNumber(args.Number)
	if err != nil {
		return err
	}

	response.Data = hexutil.Encode(validBlock.Data)
	response.Hash = hexutil.Encode(validBlock.Hash)
	response.MerkleHash = hexutil.Encode(validBlock.MerkleHash)
	response.Number = validBlock.Number
	response.PreviousBlockHash = hexutil.Encode(validBlock.PreviousBlockHash)
	response.Signature = hexutil.Encode(validBlock.Signature)
	response.Timestamp = validBlock.Timestamp
	response.Transactions = make([]JSONTransaction, len(validBlock.Transactions))
	for i, v := range validBlock.Transactions {
		response.Transactions[i] = JSONTransaction{
			Hash:            hexutil.Encode(v.Hash),
			Signature:       hexutil.Encode(v.Signature),
			PublicKey:       hexutil.Encode(v.PublicKey),
			Nounce:          hexutil.EncodeUint64BytesToHexString(v.Nounce),
			Data:            hexutil.Encode(v.Data),
			From:            v.From,
			To:              v.To,
			Value:           v.Value,
			TransactionFees: v.TransactionFees,
			Chain:           hexutil.Encode(v.Chain),
		}
	}

	return nil
}

// GetByHashArgs represents the args of rpc request.
type GetByHashArgs struct {
	Hash string `json:"hash"`
}

// GetByHash gets a block by hash.
func (api *BlockAPI) GetByHash(_ *http.Request, args *GetByHashArgs, response *JSONBlock) error {
	blockHash, err := hexutil.Decode(args.Hash)
	if err != nil {
		return err
	}

	validBlock, err := api.blockchain.GetBlockByHash(blockHash)
	if err != nil {
		return err
	}

	response.Data = hexutil.Encode(validBlock.Data)
	response.Hash = hexutil.Encode(validBlock.Hash)
	response.MerkleHash = hexutil.Encode(validBlock.MerkleHash)
	response.Number = validBlock.Number
	response.PreviousBlockHash = hexutil.Encode(validBlock.PreviousBlockHash)
	response.Signature = hexutil.Encode(validBlock.Signature)
	response.Timestamp = validBlock.Timestamp
	response.Transactions = make([]JSONTransaction, len(validBlock.Transactions))
	for i, v := range validBlock.Transactions {
		response.Transactions[i] = JSONTransaction{
			Hash:            hexutil.Encode(v.Hash),
			Signature:       hexutil.Encode(v.Signature),
			PublicKey:       hexutil.Encode(v.PublicKey),
			Nounce:          hexutil.EncodeUint64BytesToHexString(v.Nounce),
			Data:            hexutil.Encode(v.Data),
			From:            v.From,
			To:              v.To,
			Value:           v.Value,
			TransactionFees: v.TransactionFees,
			Chain:           hexutil.Encode(v.Chain),
		}
	}
	return nil
}

// EmptyArgs
type EmptyArgs struct{}

// PoolResponse represents the block pool hashes.
type PoolResponse struct {
	BlockHashes []string `json:"block_hashes"`
}

// Pool gets the block pool hashes.
// nolint:revive
func (api *BlockAPI) Pool(r *http.Request, args *EmptyArgs, response *PoolResponse) error {
	blockPool := api.blockchain.GetBlocksFromPool()
	response.BlockHashes = make([]string, len(blockPool))
	for i, v := range blockPool {
		response.BlockHashes[i] = hexutil.Encode(v.Hash)
	}

	return nil
}
