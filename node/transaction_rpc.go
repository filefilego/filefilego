package node

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"

	log "github.com/sirupsen/logrus"

	"github.com/filefilego/filefilego/common/hexutil"
	proto "google.golang.org/protobuf/proto"
)

var (
	// MaxTxDataSize represents the max size of a tx
	MaxTxDataSize = 1024 * 300
)

// TransactionAPI represents the transaction service
type TransactionAPI struct {
	Node *Node
}

// NewTransactionAPI returns a new service
func NewTransactionAPI(node *Node) *TransactionAPI {
	return &TransactionAPI{Node: node}
}

// RawTransaction represents a json trnasaction
type RawTransaction struct {
	Hash            string `json:"Hash,omitempty"`
	PubKey          string `json:"PubKey,omitempty"`
	Nounce          string `json:"Nounce,omitempty"`
	Data            string `json:"Data,omitempty"`
	From            string `json:"From,omitempty"`
	To              string `json:"To,omitempty"`
	Value           string `json:"Value,omitempty"`
	TransactionFees string `json:"TransactionFees,omitempty"`
	Chain           string `json:"Chain,omitempty"`
	Signature       string `json:"Signature,omitempty"`
}

// SendRawTransaction sends a raw transaction to the network
func (api *TransactionAPI) SendRawTransaction(ctx context.Context, tx string) (string, error) {
	tmpTx := Transaction{}
	parsedTx := RawTransaction{}
	json.Unmarshal([]byte(tx), &parsedTx)

	rawTxHash, err := hexutil.Decode(parsedTx.Hash)
	if err != nil {
		return "", err
	}

	rawTxData := []byte{}
	if parsedTx.Data != "" {
		rawTxData, err = hexutil.Decode(parsedTx.Data)
		if err != nil {
			return "", err
		}

	}

	rawTxSig, err := hexutil.Decode(parsedTx.Signature)
	if err != nil {
		return "", err
	}

	chainID, err := hexutil.Decode(parsedTx.Chain)
	if err != nil {
		return "", err
	}

	tmpTx.Chain = chainID
	tmpTx.Hash = rawTxHash
	tmpTx.PubKey = parsedTx.PubKey
	tmpTx.Nounce = parsedTx.Nounce
	tmpTx.Data = rawTxData
	tmpTx.From = parsedTx.From
	tmpTx.To = parsedTx.To
	tmpTx.Value = parsedTx.Value
	tmpTx.TransactionFees = parsedTx.TransactionFees
	tmpTx.Signature = rawTxSig

	isValid, err := api.Node.BlockChain.IsValidTransaction(tmpTx)
	if err != nil {
		return "", err
	}

	if !isValid {
		return "", errors.New("invalid/malformed transaction")
	}

	if len(tmpTx.To) > 100 || len(tmpTx.Value) > 500 || len(tmpTx.TransactionFees) > 500 || len(tmpTx.Nounce) > 100 {
		return "", errors.New("fields size too big")
	}

	if len(tmpTx.Data) > MaxTxDataSize { // 300 KB
		return "", errors.New("\"data\" field is too big")
	}

	if tmpTx.To == "" {
		return "", errors.New("\"to\" is a required field")
	}

	zero, _ := new(big.Int).SetString("0", 10)

	val, err := hexutil.DecodeBig(tmpTx.Value)
	if err != nil {
		return "", err
	}

	if val.Cmp(zero) == -1 {
		return "", errors.New("Value is negative")
	}

	txf, err := hexutil.DecodeBig(tmpTx.TransactionFees)
	if err != nil {
		txf, _ = new(big.Int).SetString("0", 10)
	}

	if txf.Cmp(zero) == -1 {
		return "", errors.New("TransactionFees is negative")
	}

	_, err = hexutil.DecodeBig(tmpTx.Nounce)
	if err != nil {
		return "", err
	}

	hasBalance, _, _, err := api.Node.BlockChain.HasThisBalance(tmpTx.From, val.Add(val, txf))
	if err != nil {
		return "", err
	}

	if hasBalance {
		err = api.Node.BlockChain.AddMemPool(tmpTx)
		if err != nil {
			return "", err
		}
		// broadcast the transaction to the network
		gpl := GossipPayload{
			Type:    GossipPayload_TRANSACTION,
			Payload: SerializeTransaction(tmpTx),
		}

		gplBts, err := proto.Marshal(&gpl)
		if err != nil {
			log.Warn("Error while marshaling transaction to protobuff: ", err)
		} else {
			// if api.Node.Peers().Len() > 1 {
			api.Node.Gossip.Broadcast(gplBts)
			// }
		}

		return hexutil.Encode(tmpTx.Hash), nil
	}

	return "", errors.New("Unable to send transaction. Check your balance")
}

// SendTransaction sends a transaction to the network
func (api *TransactionAPI) SendTransaction(ctx context.Context, accessToken string, to string, value string, txFees string, nounce string, data string) (string, error) {

	if len(to) > 100 || len(value) > 500 || len(txFees) > 500 || len(nounce) > 100 {
		return "", errors.New("fields size too big")
	}

	if len(data) > MaxTxDataSize { // 300 KB
		return "", errors.New("\"data\" field is too big")
	}

	if accessToken == "" {
		return "", errors.New("\"access_token\" is a required field")
	}

	if to == "" {
		return "", errors.New("\"to\" is a required field")
	}

	zero, _ := new(big.Int).SetString("0", 10)

	val, err := hexutil.DecodeBig(value)
	if err != nil {
		return "", err
	}

	if val.Cmp(zero) == -1 {
		return "", errors.New("Value is negative")
	}

	txf, err := hexutil.DecodeBig(txFees)
	if err != nil {
		txf, _ = new(big.Int).SetString("0", 10)
	}

	if txf.Cmp(zero) == -1 {
		return "", errors.New("TransactionFees is negative")
	}

	addrNounce, err := hexutil.DecodeBig(nounce)
	if err != nil {
		return "", err
	}

	// check if authorized token
	ok, retAddr, unlockedAccount, err := api.Node.Keystore.Authorized(accessToken)
	if err != nil {
		return "", err
	}

	if ok {
		hasBalance, _, _, err := api.Node.BlockChain.HasThisBalance(retAddr, val.Add(val, txf))
		if err != nil {
			return "", err
		}

		pbBytes, err := unlockedAccount.Key.Private.GetPublic().Raw()
		if err != nil {
			return "", err
		}

		if hasBalance {
			tx := Transaction{
				Chain:           GetBlockchainSettings().Chain,
				Data:            []byte(data),
				From:            "0x" + unlockedAccount.Key.Address,
				Nounce:          hexutil.EncodeBig(addrNounce),
				PubKey:          hexutil.Encode(pbBytes),
				To:              to,
				Value:           hexutil.EncodeBig(val),
				TransactionFees: hexutil.EncodeBig(txf),
			}
			signedTx, err := api.Node.BlockChain.SignTransaction(tx, unlockedAccount.Key)
			if err != nil {
				return "", err
			}
			err = api.Node.BlockChain.AddMemPool(signedTx)
			if err != nil {
				return "", err
			}
			// broadcast the transaction to the network
			gpl := GossipPayload{
				Type:    GossipPayload_TRANSACTION,
				Payload: SerializeTransaction(signedTx),
			}

			gplBts, err := proto.Marshal(&gpl)
			if err != nil {
				log.Warn("Error while marshaling transaction to protobuff: ", err)
			} else {
				// if api.Node.Peers().Len() > 1 {
				api.Node.Gossip.Broadcast(gplBts)
				// }
			}

			return hexutil.Encode(signedTx.Hash), nil
		}
	}

	return "", errors.New("Unable to send transaction. Check your balance")
}

// TransactionJSON for receipt payload
type TransactionJSON struct {
	Hash            string `json:"hash"`
	PubKey          string `json:"pub_key"`
	Nounce          string `json:"nounce"`
	Data            string `json:"data"`
	From            string `json:"from"`
	To              string `json:"to"`
	Value           string `json:"value"`
	TransactionFees string `json:"transaction_fees"`
	Signature       string `json:"signature"`
}

// Pool returns the mempool txs
func (api *TransactionAPI) Pool(ctx context.Context) (txs []TransactionJSON, err error) {
	for _, v := range api.Node.BlockChain.MemPool {
		t := TransactionJSON{
			Data:            hexutil.Encode(v.Data),
			From:            v.From,
			Hash:            hexutil.Encode(v.Hash),
			Nounce:          v.Nounce,
			PubKey:          v.PubKey,
			Signature:       hexutil.Encode(v.Signature),
			To:              v.To,
			TransactionFees: v.TransactionFees,
			Value:           v.Value,
		}
		txs = append(txs, t)
	}
	return txs, nil
}

// ReceiptPayload contains details of a tx
type ReceiptPayload struct {
	BlockHash   string          `json:"block_hash"`
	BlockHeight uint64          `json:"block_height"`
	Transaction TransactionJSON `json:"transaction"`
}

// Receipt gets receipts of a tx
func (api *TransactionAPI) Receipt(ctx context.Context, hash string) (txpl []ReceiptPayload, err error) {
	txs, blocks, blockHeights, err := api.Node.BlockChain.GetTransactionByHash(hash)
	if err != nil {
		return txpl, err
	}

	for i, v := range txs {
		tx := TransactionJSON{
			Data:            hexutil.Encode(v.Data),
			From:            v.From,
			Hash:            hexutil.Encode(v.Hash),
			Nounce:          v.Nounce,
			PubKey:          v.PubKey,
			Signature:       hexutil.Encode(v.Signature),
			To:              v.To,
			TransactionFees: v.TransactionFees,
			Value:           v.Value,
		}
		txpl = append(txpl, ReceiptPayload{
			BlockHash:   hexutil.Encode(blocks[i].Hash),
			BlockHeight: blockHeights[i],
			Transaction: tx,
		})

	}

	return txpl, nil
}

// ByAddress returns transactions by an address
func (api *TransactionAPI) ByAddress(ctx context.Context, address string) ([]TransactionTimestamp, error) {
	txs, err := api.Node.BlockChain.GetTransactionsByAddress(address, 20)
	if err != nil {
		return txs, err
	}

	return txs, nil
}
