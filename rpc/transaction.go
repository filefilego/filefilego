package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/keystore"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/filefilego/filefilego/transaction"
	"google.golang.org/protobuf/proto"
)

// Blockchain defines the blockchain functionality needed for this rpc service,
type Blockchain interface {
	PutMemPool(tx transaction.Transaction) error
	GetTransactionsFromPool() []transaction.Transaction
	GetAddressTransactions(address []byte, currentPage, limit int) ([]transaction.Transaction, []uint64, error)
	GetTransactionByHash(hash []byte) ([]transaction.Transaction, []uint64, error)
}

// NetworkMessagePublisher is a pub sub message broadcaster.
type NetworkMessagePublisher interface {
	PublishMessageToNetwork(ctx context.Context, data []byte) error
}

// TransactionsResponse represents a response with block and transaction
type TransactionsResponse struct {
	Transactions []JSONBlockTransaction `json:"transactions"`
}

// TransactionResponse represents a response with a transaction.
type TransactionResponse struct {
	Transaction JSONTransaction `json:"transaction"`
}

// JSONBlockTransaction represnts the block number and a transaction.
type JSONBlockTransaction struct {
	BlockNumber uint64          `json:"block_number"`
	Transaction JSONTransaction `json:"transaction"`
}

// JSONTransaction represents a json transaction.
type JSONTransaction struct {
	Hash      string `json:"hash"`
	Signature string `json:"signature"`

	PublicKey       string `json:"public_key"`
	Nounce          string `json:"nounce"`
	Data            string `json:"data"`
	From            string `json:"from"`
	To              string `json:"to"`
	Value           string `json:"value"`
	TransactionFees string `json:"transaction_fees"`
	Chain           string `json:"chain"`
}

// TransactionAPI represents the transaction rpc service.
type TransactionAPI struct {
	keystore       keystore.KeyAuthorizer
	publisher      NetworkMessagePublisher
	blockchain     Blockchain
	superLightNode bool
}

// NewTransactionAPI creates a new transaction API to be served using JSONRPC.
func NewTransactionAPI(keystore keystore.KeyAuthorizer, publisher NetworkMessagePublisher, blockchain Blockchain, superLightNode bool) (*TransactionAPI, error) {
	if keystore == nil {
		return nil, errors.New("keystore is nil")
	}

	if publisher == nil {
		return nil, errors.New("publisher is nil")
	}

	if blockchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	return &TransactionAPI{
		keystore:       keystore,
		publisher:      publisher,
		blockchain:     blockchain,
		superLightNode: superLightNode,
	}, nil
}

// SendRawTransactionArgs is a raw transaction sent by clients.
type SendRawTransactionArgs struct {
	RawTransaction string `json:"raw_transaction"`
}

// SendRawTransaction sends a raw transaction.
func (api *TransactionAPI) SendRawTransaction(r *http.Request, args *SendRawTransactionArgs, response *TransactionResponse) error {
	jsonTX := JSONTransaction{}
	if err := json.Unmarshal([]byte(args.RawTransaction), &jsonTX); err != nil {
		return fmt.Errorf("failed to unmarshal transaction: %w", err)
	}

	txHash, err := hexutil.Decode(jsonTX.Hash)
	if err != nil {
		return fmt.Errorf("failed to decode transaction hash: %w", err)
	}

	txSig, err := hexutil.Decode(jsonTX.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode transaction signature: %w", err)
	}

	txPublicKey, err := hexutil.Decode(jsonTX.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to decode transaction public key: %w", err)
	}

	txNounce, err := hexutil.DecodeUint64(jsonTX.Nounce)
	if err != nil {
		return fmt.Errorf("failed to decode transaction nounce: %w", err)
	}

	txNounceBytes := hexutil.EncodeUint64ToBytes(txNounce)

	txData, err := hexutil.Decode(jsonTX.Data)
	if err != nil {
		return fmt.Errorf("failed to decode transaction nounce: %w", err)
	}

	txChain, err := hexutil.Decode(jsonTX.Chain)
	if err != nil {
		return fmt.Errorf("failed to decode transaction chain: %w", err)
	}

	tx := transaction.Transaction{
		Hash:            txHash,
		Signature:       txSig,
		PublicKey:       txPublicKey,
		Nounce:          txNounceBytes,
		Data:            txData,
		From:            jsonTX.From,
		To:              jsonTX.To,
		Value:           jsonTX.Value,
		TransactionFees: jsonTX.TransactionFees,
		Chain:           txChain,
	}

	ok, err := tx.Validate()
	if err != nil {
		return fmt.Errorf("failed to validate raw transaction: %w", err)
	}

	if !ok {
		return errors.New("failed to validate raw transaction with false result")
	}

	return api.validateBroadcastTxSetResponse(r.Context(), &tx, response)
}

func (api *TransactionAPI) validateBroadcastTxSetResponse(ctx context.Context, tx *transaction.Transaction, response *TransactionResponse) error {
	ok, err := tx.Validate()
	if err != nil || !ok {
		return fmt.Errorf("failed to validate transaction: %w", err)
	}

	if !api.superLightNode {
		if err := api.blockchain.PutMemPool(*tx); err != nil {
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

	response.Transaction = toJSONTransaction(*tx)

	if err := api.publisher.PublishMessageToNetwork(ctx, txBytes); err != nil {
		return fmt.Errorf("failed to publish transaction to network: %w", err)
	}
	return nil
}

// SendTransactionArgs represents the arguments for sending a transaction using the client keystore mechanism.
type SendTransactionArgs struct {
	AccessToken     string `json:"access_token"`
	Nounce          string `json:"nounce"`
	Data            string `json:"data"`
	From            string `json:"from"`
	To              string `json:"to"`
	Value           string `json:"value"`
	TransactionFees string `json:"transaction_fees"`
}

// SendTransaction sends a transaction.
func (api *TransactionAPI) SendTransaction(r *http.Request, args *SendTransactionArgs, response *TransactionResponse) error {
	if args.AccessToken == "" {
		return errors.New("access token is empty")
	}

	ok, unlockedKey, err := api.keystore.Authorized(args.AccessToken)
	if err != nil || !ok {
		return errors.New("unauthorized access")
	}

	txNounce, err := hexutil.DecodeUint64(args.Nounce)
	if err != nil {
		return fmt.Errorf("failed to decode transaction nounce: %w", err)
	}

	txNounceBytes := hexutil.EncodeUint64ToBytes(txNounce)

	txData, err := hexutil.Decode(args.Data)
	if err != nil {
		return fmt.Errorf("failed to decode transaction data: %w", err)
	}

	mainChain, err := hexutil.Decode(transaction.ChainID)
	if err != nil {
		return fmt.Errorf("failed to decode chainID: %w", err)
	}

	publicKeyBytes, err := unlockedKey.Key.PublicKey.Raw()
	if err != nil {
		return fmt.Errorf("failed to get public key of unlocked account: %w", err)
	}

	tx := transaction.Transaction{
		PublicKey:       publicKeyBytes,
		Nounce:          txNounceBytes,
		Data:            txData,
		From:            args.From,
		To:              args.To,
		Value:           args.Value,
		TransactionFees: args.TransactionFees,
		Chain:           mainChain,
	}

	if err := tx.Sign(unlockedKey.Key.PrivateKey); err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	return api.validateBroadcastTxSetResponse(r.Context(), &tx, response)
}

// MemPoolResponse represents the mempool hashes.
type MemPoolResponse struct {
	TransactionHashes []string `json:"transaction_hashes"`
}

// Pool gets the list of transactions in mempool.
func (api *TransactionAPI) Pool(r *http.Request, args *EmptyArgs, response *MemPoolResponse) error {
	memPool := api.blockchain.GetTransactionsFromPool()
	response.TransactionHashes = make([]string, len(memPool))
	for i, v := range memPool {
		response.TransactionHashes[i] = hexutil.Encode(v.Hash)
	}
	return nil
}

// ReceiptArgs receipt arguments.
type ReceiptArgs struct {
	Hash string `json:"hash"`
}

// Receipt gets the transaction receipt.
func (api *TransactionAPI) Receipt(r *http.Request, args *ReceiptArgs, response *TransactionsResponse) error {
	transactionBytes, err := hexutil.Decode(args.Hash)
	if err != nil {
		return err
	}

	transactions, blockNumbers, err := api.blockchain.GetTransactionByHash(transactionBytes)
	if err != nil {
		return err
	}

	response.Transactions = make([]JSONBlockTransaction, 0)

	for i, tx := range transactions {
		jtx := toJSONTransaction(tx)
		receipt := JSONBlockTransaction{
			BlockNumber: blockNumbers[i],
			Transaction: jtx,
		}
		response.Transactions = append(response.Transactions, receipt)
	}

	return nil
}

// ByAddressArgs get transactions by address arguments.
type ByAddressArgs struct {
	Address     string `json:"address"`
	CurrentPage int    `json:"current_page"`
	PageSize    int    `json:"page_size"`
}

// ByAddress gets the list of transactions by address.
func (api *TransactionAPI) ByAddress(r *http.Request, args *ByAddressArgs, response *TransactionsResponse) error {
	addressBytes, err := hexutil.Decode(args.Address)
	if err != nil {
		return err
	}

	transactions, blockNumbers, err := api.blockchain.GetAddressTransactions(addressBytes, args.CurrentPage, args.PageSize)
	if err != nil {
		return err
	}
	response.Transactions = make([]JSONBlockTransaction, 0)
	for i, tx := range transactions {
		jtx := toJSONTransaction(tx)
		receipt := JSONBlockTransaction{
			BlockNumber: blockNumbers[i],
			Transaction: jtx,
		}
		response.Transactions = append(response.Transactions, receipt)
	}

	return nil
}

func toJSONTransaction(t transaction.Transaction) JSONTransaction {
	return JSONTransaction{
		Hash:            hexutil.Encode(t.Hash),
		Signature:       hexutil.Encode(t.Signature),
		PublicKey:       hexutil.Encode(t.PublicKey),
		Nounce:          hexutil.EncodeUint64BytesToHexString(t.Nounce),
		Data:            hexutil.Encode(t.Data),
		From:            t.From,
		To:              t.To,
		Value:           t.Value,
		TransactionFees: t.TransactionFees,
		Chain:           hexutil.Encode(t.Chain),
	}
}
