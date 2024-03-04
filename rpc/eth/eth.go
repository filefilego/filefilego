package eth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	ffgcommon "github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/filefilego/filefilego/transaction"
	"google.golang.org/protobuf/proto"
)

const (
	// 0.001 FFG = 47619047620 (fee per gas)  * 21000 (gas limit)
	blockBaseFees = 47619047620
)

// NetworkMessagePublisher is a pub sub message broadcaster.
type NetworkMessagePublisher interface {
	PublishMessageToNetwork(ctx context.Context, topicName string, data []byte) error
}

type bcInterface interface {
	GetHeight() uint64
	GetAddressState(address []byte) (blockchain.AddressState, error)
	GetBlockByNumber(blockNumber uint64) (*block.Block, error)
	PutMemPool(tx transaction.Transaction) error
	GetTransactionByHash(hash []byte) ([]transaction.Transaction, []uint64, error)
	GetBlockByHash(blockHash []byte) (block.Block, error)
}

type EmptyArgs struct{}

// API represents eth service
type API struct {
	chainID        string
	bc             bcInterface
	superLightNode bool
	publisher      NetworkMessagePublisher
}

// NewAPI creates a new address API to be served using JSONRPC.
func NewAPI(blockchain bcInterface, chainID string, publisher NetworkMessagePublisher, superLightNode bool) (*API, error) {
	if blockchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	if chainID == "" {
		return nil, errors.New("chainID is nil")
	}

	if publisher == nil {
		return nil, errors.New("publisher is nil")
	}

	return &API{
		chainID:        chainID,
		bc:             blockchain,
		publisher:      publisher,
		superLightNode: superLightNode,
	}, nil
}

// ChainIDResponse
type ChainIDResponse string

// ChainID returns chain id.
func (api *API) ChainID(_ *http.Request, _ *EmptyArgs, response *ChainIDResponse) error {
	*response = ChainIDResponse(api.chainID)
	return nil
}

// BlockNumberResponse is a key unlock response.
type BlockNumberResponse string

// BlockNumber returns the block height.
func (api *API) BlockNumber(_ *http.Request, _ *EmptyArgs, response *BlockNumberResponse) error {
	height := hexutil.EncodeUint64(api.bc.GetHeight())

	*response = BlockNumberResponse(height)
	return nil
}

type GetBalanceResponse string

type GetBalanceArgs []interface{}

// GetBalance returns the address balance.
func (api *API) GetBalance(_ *http.Request, args *GetBalanceArgs, response *GetBalanceResponse) error {
	arg1, ok := (*args)[0].(string)
	if !ok {
		return errors.New("invalid address")
	}

	addr, err := hexutil.Decode(arg1)
	if err != nil {
		return fmt.Errorf("failed to decode address: %w", err)
	}

	state, err := api.bc.GetAddressState(addr)
	if err != nil {
		*response = GetBalanceResponse("0x0")
		return nil
	}

	balance, err := state.GetBalance()
	if reflect.ValueOf(balance).IsNil() || balance == nil || err != nil {
		*response = GetBalanceResponse("0x0")
		return nil
	}

	balanceHex := hexutil.EncodeBig(balance)

	*response = GetBalanceResponse(balanceHex)
	return nil
}

// Version returns chain id in human readable format.
func (api *API) Version(_ *http.Request, _ *EmptyArgs, response *ChainIDResponse) error {
	chain, _ := hexutil.DecodeBig(api.chainID)
	*response = ChainIDResponse(fmt.Sprintf("%d", chain.Uint64()))
	return nil
}

// GasPriceResponse
type GasPriceResponse string

// GasPrice returns the gas price.
func (api *API) GasPrice(_ *http.Request, _ *EmptyArgs, response *GasPriceResponse) error {
	*response = GasPriceResponse(hexutil.EncodeBig(big.NewInt(blockBaseFees)))
	return nil
}

type EstimateGasResponse string

type EstimateGasArgs struct {
	Data     string `json:"data"`
	From     string `json:"from"`
	To       string `json:"to"`
	GasPrice string `json:"gasPrice"`
	Value    string `json:"value"`
}

// EstimateGas returns the estimated gas.
func (api *API) EstimateGas(_ *http.Request, args *EstimateGasArgs, response *EstimateGasResponse) error {
	defualtGas := big.NewInt(transaction.GasLimitFromFFGNetwork)
	*response = EstimateGasResponse(hexutil.EncodeBig(defualtGas))
	return nil
}

type GetTransactionCountResponse string

type GetTransactionCountArgs []interface{}

// GetTransactionCount returns the transaction counts of an address.
func (api *API) GetTransactionCount(_ *http.Request, args *GetTransactionCountArgs, response *GetTransactionCountResponse) error {
	arg1, ok := (*args)[0].(string)
	if !ok {
		return errors.New("invalid address")
	}

	addr, err := hexutil.Decode(arg1)
	if err != nil {
		return fmt.Errorf("failed to decode address: %w", err)
	}

	state, err := api.bc.GetAddressState(addr)
	if err != nil {
		*response = GetTransactionCountResponse("0x1")
		return nil
	}

	nounce, err := state.GetNounce()
	if err != nil {
		*response = GetTransactionCountResponse("0x1")
		return nil
	}

	if nounce == 0 {
		nounce = 1
	} else {
		nounce++
	}

	*response = GetTransactionCountResponse(hexutil.EncodeUint64(nounce))
	return nil
}

type GetCodeResponse string

type GetCodeArgs []interface{}

// GetCode returns 0x
func (api *API) GetCode(_ *http.Request, _ *GetCodeArgs, response *GetCodeResponse) error {
	*response = "0x"
	return nil
}

type GetBlockByNumberArgs []interface{}

type GetBlockByNumberResponse struct {
	BaseFeePerGas    string        `json:"baseFeePerGas"`
	Difficulty       string        `json:"difficulty"`
	ExtraData        string        `json:"extraData"`
	GasLimit         string        `json:"gasLimit"`
	GasUsed          string        `json:"gasUsed"`
	Hash             string        `json:"hash"`
	LogsBloom        string        `json:"logsBloom"`
	Miner            string        `json:"miner"`
	MixHash          string        `json:"mixHash"`
	Nonce            string        `json:"nonce"`
	Number           string        `json:"number"`
	ParentHash       string        `json:"parentHash"`
	ReceiptsRoot     string        `json:"receiptsRoot"`
	Sha3Uncles       string        `json:"sha3Uncles"`
	Size             string        `json:"size"`
	StateRoot        string        `json:"stateRoot"`
	Timestamp        string        `json:"timestamp"`
	TotalDifficulty  string        `json:"totalDifficulty"`
	Transactions     []string      `json:"transactions"`
	TransactionsRoot string        `json:"transactionsRoot"`
	Uncles           []interface{} `json:"uncles"`
	Withdrawals      []Withdrawal  `json:"withdrawals"`
	WithdrawalsRoot  string        `json:"withdrawalsRoot"`
}

type Withdrawal struct {
	Address        string `json:"address"`
	Amount         string `json:"amount"`
	Index          string `json:"index"`
	ValidatorIndex string `json:"validatorIndex"`
}

func (api *API) GetBlockByNumber(_ *http.Request, args *GetBlockByNumberArgs, response *GetBlockByNumberResponse) error {
	arg1, ok := (*args)[0].(string)
	if !ok {
		return errors.New("invalid block number")
	}

	blockNo, err := hexutil.DecodeBig(arg1)
	if err != nil {
		return errors.New("invalid block number hex")
	}

	block, err := api.bc.GetBlockByNumber(blockNo.Uint64())
	if err != nil {
		return fmt.Errorf("failed to get block: %w", err)
	}

	// coinbaseTx, err := block.GetAndValidateCoinbaseTransaction()
	// if err != nil {
	// 	return fmt.Errorf("failed to get block's coinbase transaction: %w", err)
	// }

	transactions := make([]*ethTypes.Transaction, 0)
	for _, v := range block.Transactions {
		if v.Type() != transaction.LegacyTxType {
			innerEth := v.InnerEth()
			transactions = append(transactions, innerEth)
		}
	}

	ethBlock := getEthBlock(big.NewInt(0).SetUint64(block.Number), uint64(block.Timestamp), block.PreviousBlockHash, transactions)
	parentHash := ethBlock.ParentHash().Hex()
	response.BaseFeePerGas = hexutil.EncodeBig(ethBlock.BaseFee())
	response.Difficulty = hexutil.EncodeBig(ethBlock.Difficulty())

	response.ExtraData = hexutil.Encode(block.Data)
	response.GasLimit = hexutil.EncodeUint64(ethBlock.GasLimit())
	response.GasUsed = hexutil.EncodeUint64(ethBlock.GasUsed())
	response.Hash = ethBlock.Hash().Hex()
	response.LogsBloom = hexutil.Encode(ethBlock.Bloom().Bytes())

	response.Miner = ethBlock.Coinbase().Hex()

	response.MixHash = ethBlock.MixDigest().Hex()
	response.Nonce = hexutil.EncodeUint64(ethBlock.Nonce())
	response.Number = arg1
	response.ParentHash = parentHash
	response.ReceiptsRoot = ethBlock.ReceiptHash().Hex()
	response.Sha3Uncles = ethBlock.UncleHash().Hex()
	response.Size = hexutil.EncodeUint64(ethBlock.Size())
	response.StateRoot = ethBlock.Root().Hex()
	response.Timestamp = hexutil.EncodeUint64(ethBlock.Time())
	response.TotalDifficulty = hexutil.EncodeBig(ethBlock.Difficulty())
	response.Transactions = make([]string, len(block.Transactions))
	for i, v := range block.Transactions {
		response.Transactions[i] = hexutil.Encode(v.Hash())
	}
	response.TransactionsRoot = ethBlock.TxHash().Hex()
	response.Uncles = make([]interface{}, 0)
	response.Withdrawals = []Withdrawal{}
	// response.WithdrawalsRoot = ethBlock.Header().WithdrawalsHash.Hex()

	return nil
}

func getEthBlock(blockNumber *big.Int, timestamp uint64, parentHash []byte, txs []*ethTypes.Transaction) *ethTypes.Block {
	header := &ethTypes.Header{
		BaseFee:    big.NewInt(blockBaseFees),
		Difficulty: big.NewInt(0),
		Number:     blockNumber,
		GasLimit:   uint64(transaction.GasLimitFromFFGNetwork * 2), // gas limit will be 2x more than gas used.
		GasUsed:    uint64(transaction.GasLimitFromFFGNetwork),
		Time:       timestamp,
		ParentHash: common.BytesToHash(parentHash),
	}

	receipts := make([]*ethTypes.Receipt, len(txs))
	for i, v := range txs {
		receipts[i] = ethTypes.NewReceipt(make([]byte, 32), false, v.Gas())
	}

	return ethTypes.NewBlock(header, txs, []*ethTypes.Header{}, receipts, trie.NewStackTrie(nil))
}

func (api *API) GetBlockByHash(_ *http.Request, args *GetBlockByNumberArgs, response *GetBlockByNumberResponse) error {
	arg1, ok := (*args)[0].(string)
	if !ok {
		return errors.New("invalid block number")
	}

	blockHash, err := hexutil.Decode(arg1)
	if err != nil {
		return errors.New("invalid block number hex")
	}

	block, err := api.bc.GetBlockByHash(blockHash)
	if err != nil {
		return fmt.Errorf("failed to get block: %w", err)
	}

	// coinbaseTx, err := block.GetAndValidateCoinbaseTransaction()
	// if err != nil {
	// 	return fmt.Errorf("failed to get block's coinbase transaction: %w", err)
	// }

	transactions := make([]*ethTypes.Transaction, 0)
	for _, v := range block.Transactions {
		if v.Type() != transaction.LegacyTxType {
			innerEth := v.InnerEth()
			transactions = append(transactions, innerEth)
		}
	}

	ethBlock := getEthBlock(big.NewInt(0).SetUint64(block.Number), uint64(block.Timestamp), block.PreviousBlockHash, transactions)
	parentHash := ethBlock.ParentHash().Hex()
	response.BaseFeePerGas = hexutil.EncodeBig(ethBlock.BaseFee())
	response.Difficulty = hexutil.EncodeBig(ethBlock.Difficulty())

	response.ExtraData = hexutil.Encode(block.Data)
	response.GasLimit = hexutil.EncodeUint64(ethBlock.GasLimit())
	response.GasUsed = hexutil.EncodeUint64(ethBlock.GasUsed())
	response.Hash = ethBlock.Hash().Hex()
	response.LogsBloom = hexutil.Encode(ethBlock.Bloom().Bytes())

	response.Miner = ethBlock.Coinbase().Hex()

	response.MixHash = ethBlock.MixDigest().Hex()
	response.Nonce = hexutil.EncodeUint64(ethBlock.Nonce())
	response.Number = arg1
	response.ParentHash = parentHash
	response.ReceiptsRoot = ethBlock.ReceiptHash().Hex()
	response.Sha3Uncles = ethBlock.UncleHash().Hex()
	response.Size = hexutil.EncodeUint64(ethBlock.Size())
	response.StateRoot = ethBlock.Root().Hex()
	response.Timestamp = hexutil.EncodeUint64(ethBlock.Time())
	response.TotalDifficulty = hexutil.EncodeBig(ethBlock.Difficulty())
	response.Transactions = make([]string, len(block.Transactions))
	for i, v := range block.Transactions {
		response.Transactions[i] = hexutil.Encode(v.Hash())
	}
	response.TransactionsRoot = ethBlock.TxHash().Hex()
	response.Uncles = make([]interface{}, 0)
	response.Withdrawals = []Withdrawal{}
	// response.WithdrawalsRoot = ethBlock.Header().WithdrawalsHash.Hex()

	return nil
}

type SendRawTransactionArgs []interface{}

type SendRawTransactionResponse string

// SendRawTransaction sends a raw transaction.
func (api *API) SendRawTransaction(r *http.Request, args *SendRawTransactionArgs, response *SendRawTransactionResponse) error {
	arg1, ok := (*args)[0].(string)
	if !ok {
		return errors.New("invalid tx data")
	}

	log.Infof("raw transaction submited: %s", arg1)

	tx, err := transaction.ParseEth(strings.TrimPrefix(arg1, "0x"))
	if err != nil {
		return fmt.Errorf("failed to parse eth transaction: %w", err)
	}

	ok, err = tx.Validate()
	if err != nil {
		fmt.Println("raw tx error ", arg1, hexutil.Encode(tx.Hash()))
		return fmt.Errorf("failed to validate transaction with error: %w", err)
	}
	if !ok {
		return errors.New("failed to validate transaction")
	}

	if !api.superLightNode {
		if err := api.bc.PutMemPool(*tx); err != nil {
			return fmt.Errorf("failed to insert transaction from rpc method to mempool: %w", err)
		}
	}

	payload := messages.GossipPayload{
		Message: &messages.GossipPayload_Transaction{
			Transaction: transaction.ToProtoTransaction(*tx),
		},
	}

	txBytes, err := proto.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("failed to marshal gossip payload: %w", err)
	}

	if err := api.publisher.PublishMessageToNetwork(r.Context(), ffgcommon.FFGNetPubSubBlocksTXQuery, txBytes); err != nil {
		return fmt.Errorf("failed to publish transaction to network: %w", err)
	}

	txHash := hexutil.Encode(tx.Hash())
	*response = SendRawTransactionResponse(txHash)
	return nil
}

type GetTransactionByHashArgs []interface{}

// Transaction represents an Ethereum transaction.
type GetTransactionByHashResponse struct {
	BlockHash            string   `json:"blockHash"`
	BlockNumber          string   `json:"blockNumber"`
	From                 string   `json:"from"`
	Gas                  string   `json:"gas"`
	GasPrice             string   `json:"gasPrice"`
	MaxFeePerGas         string   `json:"maxFeePerGas"`
	MaxPriorityFeePerGas string   `json:"maxPriorityFeePerGas"`
	Hash                 string   `json:"hash"`
	Input                string   `json:"input"`
	Nonce                string   `json:"nonce"`
	To                   string   `json:"to"`
	TransactionIndex     string   `json:"transactionIndex"`
	Value                string   `json:"value"`
	Type                 string   `json:"type"`
	AccessList           []string `json:"accessList"`
	V                    string   `json:"v"`
	R                    string   `json:"r"`
	S                    string   `json:"s"`
	ChainID              string   `json:"chainId,omitempty"`
}

// SendRawTransaction gets the transaction by hash.
func (api *API) GetTransactionByHash(_ *http.Request, args *GetTransactionByHashArgs, response *GetTransactionByHashResponse) error {
	txHash, ok := (*args)[0].(string)
	if !ok {
		return errors.New("invalid tx data")
	}

	h, err := hexutil.Decode(txHash)
	if err != nil {
		return fmt.Errorf("failed to decode transaction hash: %w", err)
	}

	txs, blockNumbers, err := api.bc.GetTransactionByHash(h)
	if err != nil || len(txs) == 0 {
		response = nil
		return nil
	}

	block, err := api.bc.GetBlockByNumber(blockNumbers[0])
	if err != nil {
		return fmt.Errorf("failed to get block: %w", err)
	}

	txIndex := -1

	for i, v := range block.Transactions {
		if bytes.Equal(v.Hash(), h) {
			txIndex = i
		}
	}

	if txIndex == -1 {
		return fmt.Errorf("failed to find transaction in block: %w", err)
	}

	response.AccessList = []string{}
	response.BlockHash = hexutil.Encode(block.Hash)
	response.BlockNumber = hexutil.EncodeBig(big.NewInt(0).SetUint64(blockNumbers[0]))
	response.TransactionIndex = hexutil.EncodeInt64(int64(txIndex))
	response.ChainID = api.chainID
	response.From = txs[0].From()
	response.Gas = hexutil.EncodeBig(big.NewInt(0).SetBytes(txs[0].GasLimit()))
	response.GasPrice = txs[0].TransactionFees()
	response.Hash = hexutil.Encode(txs[0].Hash())
	response.Input = hexutil.Encode(txs[0].Data())

	if txs[0].EthType() == transaction.EthDynamicFeeTxType {
		// for dynamic transaction fees, we store MaxFeePerGas inside TransactionFees
		response.MaxFeePerGas = txs[0].TransactionFees()
		// response.MaxPriorityFeePerGas = hexutil.EncodeBig(big.NewInt(0).SetBytes(txs[0].GasTip()))
		response.MaxPriorityFeePerGas = "0x0"
	}

	response.Nonce = hexutil.EncodeBig(big.NewInt(0).SetBytes(txs[0].Nounce()))
	response.R = hexutil.Encode(txs[0].Signature()[:32])
	response.S = hexutil.Encode(txs[0].Signature()[32:64])
	response.V = hexutil.Encode(txs[0].Signature()[64:])
	response.To = txs[0].To()
	response.Type = hexutil.EncodeInt64(int64(txs[0].EthType()))
	response.Value = txs[0].Value()

	return nil
}

type GetTransactionReceiptArgs []interface{}

type GetTransactionReceiptResponse struct {
	TransactionHash   string   `json:"transactionHash"`
	TransactionIndex  string   `json:"transactionIndex"`
	BlockHash         string   `json:"blockHash"`
	BlockNumber       string   `json:"blockNumber"`
	From              string   `json:"from"`
	To                string   `json:"to"`
	CumulativeGasUsed string   `json:"cumulativeGasUsed"`
	EffectiveGasPrice string   `json:"effectiveGasPrice"`
	GasUsed           string   `json:"gasUsed"`
	ContractAddress   string   `json:"contractAddress,omitempty"`
	Logs              []string `json:"logs"`
	Status            string   `json:"status"` // 0x1 indicates success, 0x0 indicates failure
	LogsBloom         string   `json:"logsBloom"`
}

// GetTransactionReceipt get's transaction receipt.
func (api *API) GetTransactionReceipt(_ *http.Request, args *GetTransactionReceiptArgs, response *GetTransactionReceiptResponse) error {
	txHash, ok := (*args)[0].(string)
	if !ok {
		return errors.New("invalid tx data")
	}

	h, err := hexutil.Decode(txHash)
	if err != nil {
		return fmt.Errorf("failed to decode transaction hash: %w", err)
	}

	txs, blockNumbers, err := api.bc.GetTransactionByHash(h)
	if err != nil || len(txs) == 0 {
		response = nil
		return nil
	}

	block, err := api.bc.GetBlockByNumber(blockNumbers[0])
	if err != nil {
		return fmt.Errorf("failed to get block: %w", err)
	}

	txIndex := -1

	for i, v := range block.Transactions {
		if bytes.Equal(v.Hash(), h) {
			txIndex = i
		}
	}

	if txIndex == -1 {
		return fmt.Errorf("failed to find transaction in block: %w", err)
	}

	response.BlockHash = hexutil.Encode(block.Hash)
	response.BlockNumber = hexutil.EncodeBig(big.NewInt(0).SetUint64(blockNumbers[0]))
	response.CumulativeGasUsed = hexutil.EncodeBig(big.NewInt(0).SetBytes(txs[0].GasLimit()))
	response.EffectiveGasPrice = txs[0].TransactionFees()
	response.From = txs[0].From()
	response.GasUsed = hexutil.EncodeBig(big.NewInt(0).SetBytes(txs[0].GasLimit()))
	response.Logs = []string{}
	response.LogsBloom = ""
	response.Status = "0x1"
	response.To = txs[0].To()
	response.TransactionHash = hexutil.Encode(txs[0].Hash())
	response.TransactionIndex = hexutil.EncodeInt64(int64(txIndex))

	return nil
}
