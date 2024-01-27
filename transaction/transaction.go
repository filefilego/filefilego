package transaction

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/cbergoon/merkletree"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/filefilego/filefilego/common/hexutil"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
	"github.com/libp2p/go-libp2p/core/crypto"
)

// ChainID represents the main-net chain id.
const ChainID = "0x01"

const maxTransactionDataSizeBytes = 300000

const (
	LegacyTxType = 0
	EthTxType    = 1
)

// Transaction represents a transaction.
type Transaction struct {
	// calculated after
	hash      []byte
	signature []byte

	// required
	publicKey       []byte
	nounce          []byte
	data            []byte
	from            string
	to              string
	value           string
	transactionFees string
	chain           []byte

	// additions
	txType uint8
	// gas    string
}

func NewTransaction(publicKey, nounce, data []byte, from, to, value, transactionFees string, chain []byte) *Transaction {
	tx := &Transaction{
		publicKey:       make([]byte, len(publicKey)),
		nounce:          make([]byte, len(nounce)),
		data:            make([]byte, len(data)),
		from:            from,
		to:              to,
		value:           value,
		transactionFees: transactionFees,
		chain:           make([]byte, len(chain)),
	}

	copy(tx.publicKey, publicKey)
	copy(tx.nounce, nounce)
	copy(tx.data, data)
	copy(tx.chain, chain)

	return tx
}

func (tx *Transaction) SetHash(hash []byte) *Transaction {
	tx.hash = make([]byte, len(hash))
	copy(tx.hash, hash)
	return tx
}

func (tx *Transaction) SetSignature(sig []byte) *Transaction {
	tx.signature = make([]byte, len(sig))
	copy(tx.signature, sig)
	return tx
}

func (tx *Transaction) SetTransactionFees(txFees string) *Transaction {
	tx.transactionFees = txFees
	return tx
}

func (tx *Transaction) Hash() []byte {
	return tx.hash
}

func (tx *Transaction) Signature() []byte {
	return tx.signature
}

func (tx *Transaction) PublicKey() []byte {
	return tx.publicKey
}

func (tx *Transaction) SetPublicKey(pubkeyData []byte) *Transaction {
	tx.publicKey = make([]byte, len(pubkeyData))
	copy(tx.publicKey, pubkeyData)
	return tx
}

func (tx *Transaction) Nounce() []byte {
	return tx.nounce
}

func (tx *Transaction) Data() []byte {
	return tx.data
}

func (tx *Transaction) From() string {
	return tx.from
}

func (tx *Transaction) To() string {
	return tx.to
}

func (tx *Transaction) Value() string {
	return tx.value
}

func (tx *Transaction) TransactionFees() string {
	return tx.transactionFees
}

func (tx *Transaction) Chain() []byte {
	return tx.chain
}

func (tx *Transaction) TxType() uint8 {
	return tx.txType
}

func NewEthTX(rawTX string) (*Transaction, error) {
	var ethTx ethTypes.Transaction
	txData, err := hexutil.DecodeNoPrefix(rawTX)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %w", err)
	}

	derivedTX, err := &ethTx, rlp.DecodeBytes(txData, &ethTx)
	if err != nil {
		return nil, fmt.Errorf("failed to decode rpl bytes: %w", err)
	}

	// derivedTX.

	tx := &Transaction{
		txType: EthTxType,
		hash:   derivedTX.Hash().Bytes(),
		// Nounce: ,
	}

	return tx, nil
}

// serialize the transaction to bytes.
func (tx *Transaction) serialize() ([]byte, error) {
	mainChain, err := hexutil.Decode(ChainID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode chainID: %w", err)
	}

	if len(tx.publicKey) == 0 {
		return nil, errors.New("publicKey is empty")
	}

	if len(tx.nounce) == 0 {
		return nil, errors.New("nounce is empty")
	}

	if tx.from == "" {
		return nil, errors.New("from is empty")
	}

	if tx.to == "" {
		return nil, errors.New("to is empty")
	}

	if tx.value == "" {
		return nil, errors.New("value is empty")
	}

	if tx.transactionFees == "" {
		return nil, errors.New("transactionFees is empty")
	}

	data := bytes.Join(
		[][]byte{
			tx.publicKey,
			tx.nounce,
			tx.data,
			[]byte(tx.from),
			[]byte(tx.to),
			[]byte(tx.value),
			[]byte(tx.transactionFees),
			mainChain,
		},
		[]byte{},
	)
	return data, nil
}

// CalculateHash gets a hash of a transaction.
func (tx *Transaction) CalculateHash() ([]byte, error) {
	data, err := tx.serialize()
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Equals tests for equality of two Contents.
func (tx *Transaction) Equals(other merkletree.Content) (bool, error) {
	data, err := tx.serialize()
	if err != nil {
		return false, err
	}

	dataOther, err := other.(*Transaction).serialize()
	if err != nil {
		return false, err
	}

	return bytes.Equal(data, dataOther), nil
}

// SignTransaction signs a transaction with a private key.
func (tx *Transaction) Sign(key crypto.PrivKey) error {
	hash, err := tx.CalculateHash()
	if err != nil {
		return fmt.Errorf("failed to get transactionHash: %w", err)
	}

	tx.hash = make([]byte, len(hash))
	copy(tx.hash, hash)

	sig, err := key.Sign(tx.hash)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	tx.signature = make([]byte, len(sig))
	copy(tx.signature, sig)

	return nil
}

// VerifyWithPublicKey verifies a transaction with a public key.
func (tx *Transaction) VerifyWithPublicKey(key crypto.PubKey) error {
	ok, err := key.Verify(tx.hash, tx.signature)
	if err != nil {
		return fmt.Errorf("failed to verify transaction: %w", err)
	}
	if !ok {
		return errors.New("failed verification of transaction")
	}
	return nil
}

// Validate a transaction.
func (tx *Transaction) Validate() (bool, error) {
	zero := big.NewInt(0)
	if len(tx.hash) == 0 || tx.hash == nil {
		return false, errors.New("hash is empty")
	}

	if len(tx.data) > maxTransactionDataSizeBytes {
		return false, fmt.Errorf("data with size %d is greater than %d bytes", len(tx.data), maxTransactionDataSizeBytes)
	}

	mainChain, err := hexutil.Decode(ChainID)
	if err != nil {
		return false, fmt.Errorf("failed to decode chainID: %w", err)
	}

	if !bytes.Equal(tx.chain, mainChain) {
		return false, errors.New("wrong chain")
	}

	if tx.from == "" {
		return false, errors.New("from is empty")
	}

	if tx.to == "" {
		return false, errors.New("to is empty")
	}

	if len(tx.nounce) == 0 {
		return false, errors.New("nounce is empty")
	}

	if len(tx.publicKey) == 0 {
		return false, errors.New("publicKey is empty")
	}

	if tx.transactionFees == "" {
		return false, errors.New("transactionFees is empty")
	}

	if tx.value == "" {
		return false, errors.New("value is empty")
	}

	val, err := hexutil.DecodeBig(tx.value)
	if err != nil {
		return false, fmt.Errorf("value is malformed: %w", err)
	}

	if val.Cmp(zero) == -1 {
		return false, errors.New("value is negative")
	}

	valFees, err := hexutil.DecodeBig(tx.transactionFees)
	if err != nil {
		return false, fmt.Errorf("failed to decode transactionFees: %w", err)
	}
	if valFees.Cmp(zero) == -1 {
		return false, errors.New("transactionFees is negative")
	}

	hash, err := tx.CalculateHash()
	if err != nil {
		return false, errors.New("failed to get transaction hash")
	}

	if !bytes.Equal(tx.hash, hash) {
		return false, errors.New("transaction is altered and doesn't match the hash")
	}

	newPubKey, err := ffgcrypto.PublicKeyFromBytes(tx.publicKey)
	if err != nil {
		return false, fmt.Errorf("failed to get publicKey: %w", err)
	}

	err = tx.VerifyWithPublicKey(newPubKey)
	if err != nil {
		return false, fmt.Errorf("failed to verify: %w", err)
	}

	fromAddr, err := ffgcrypto.RawPublicToAddress(tx.publicKey)
	if err != nil {
		return false, fmt.Errorf("failed to get address from publicKey: %w", err)
	}

	if tx.from != fromAddr {
		return false, errors.New("from address doesn't match the public key")
	}

	return true, nil
}

// ToProtoTransaction converts a transaction to protobuf message.
func ToProtoTransaction(tx Transaction) *ProtoTransaction {
	ptx := &ProtoTransaction{
		Hash:            make([]byte, len(tx.hash)),
		Signature:       make([]byte, len(tx.signature)),
		PublicKey:       make([]byte, len(tx.publicKey)),
		Nounce:          make([]byte, len(tx.nounce)),
		Data:            make([]byte, len(tx.data)),
		From:            tx.from,
		To:              tx.to,
		Value:           tx.value,
		TransactionFees: tx.transactionFees,
		Chain:           make([]byte, len(tx.chain)),
	}

	copy(ptx.Hash, tx.hash)
	copy(ptx.Signature, tx.signature)
	copy(ptx.PublicKey, tx.publicKey)
	copy(ptx.Nounce, tx.nounce)
	copy(ptx.Data, tx.data)
	copy(ptx.Chain, tx.chain)

	return ptx
}

// ProtoTransactionToTransaction returns a domain transaction from a protobuf message.
func ProtoTransactionToTransaction(ptx *ProtoTransaction) Transaction {
	tx := Transaction{
		hash:            make([]byte, len(ptx.Hash)),
		signature:       make([]byte, len(ptx.Signature)),
		publicKey:       make([]byte, len(ptx.PublicKey)),
		nounce:          make([]byte, len(ptx.Nounce)),
		data:            make([]byte, len(ptx.Data)),
		from:            ptx.From,
		to:              ptx.To,
		value:           ptx.Value,
		transactionFees: ptx.TransactionFees,
		chain:           make([]byte, len(ptx.Chain)),
	}

	copy(tx.hash, ptx.Hash)
	copy(tx.signature, ptx.Signature)
	copy(tx.publicKey, ptx.PublicKey)
	copy(tx.nounce, ptx.Nounce)
	copy(tx.data, ptx.Data)
	copy(tx.chain, ptx.Chain)

	return tx
}
