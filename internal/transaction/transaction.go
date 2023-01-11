package transaction

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/cbergoon/merkletree"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	ffgcrypto "github.com/filefilego/filefilego/internal/crypto"
	"github.com/libp2p/go-libp2p/core/crypto"
	"google.golang.org/protobuf/proto"
)

const chainID = "0x01"

const maxTransactionDataSizeBytes = 300000

// Transaction represents a transaction.
type Transaction struct {
	// calculated after
	Hash      []byte
	Signature []byte

	// required
	PublicKey       []byte
	Nounce          []byte
	Data            []byte
	From            string
	To              string
	Value           string
	TransactionFees string
	Chain           []byte
}

// Serialize the transaction to bytes.
func (tx Transaction) Serialize() ([]byte, error) {
	mainChain, err := hexutil.Decode(chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode chainID: %w", err)
	}

	if len(tx.PublicKey) == 0 {
		return nil, errors.New("publicKey is empty")
	}

	if len(tx.Nounce) == 0 {
		return nil, errors.New("nounce is empty")
	}

	if tx.From == "" {
		return nil, errors.New("from is empty")
	}

	if tx.To == "" {
		return nil, errors.New("to is empty")
	}

	if tx.Value == "" {
		return nil, errors.New("value is empty")
	}

	if tx.TransactionFees == "" {
		return nil, errors.New("transactionFees is empty")
	}

	data := bytes.Join(
		[][]byte{
			tx.PublicKey,
			tx.Nounce,
			tx.Data,
			[]byte(tx.From),
			[]byte(tx.To),
			[]byte(tx.Value),
			[]byte(tx.TransactionFees),
			mainChain,
		},
		[]byte{},
	)
	return data, nil
}

// CalculateHash gets a hash of a transaction.
func (tx Transaction) CalculateHash() ([]byte, error) {
	data, err := tx.Serialize()
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
func (tx Transaction) Equals(other merkletree.Content) (bool, error) {
	data, err := tx.Serialize()
	if err != nil {
		return false, err
	}

	dataOther, err := other.(Transaction).Serialize()
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

	tx.Hash = make([]byte, len(hash))
	copy(tx.Hash, hash)

	sig, err := key.Sign(tx.Hash)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	tx.Signature = make([]byte, len(sig))
	copy(tx.Signature, sig)

	return nil
}

// VerifyWithPublicKey verifies a transaction with a public key.
func (tx Transaction) VerifyWithPublicKey(key crypto.PubKey) error {
	ok, err := key.Verify(tx.Hash, tx.Signature)
	if err != nil {
		return fmt.Errorf("failed to verify transaction: %w", err)
	}
	if !ok {
		return errors.New("failed verification of transaction")
	}
	return nil
}

// Validate a transaction.
func (tx Transaction) Validate() (bool, error) {
	zero, _ := new(big.Int).SetString("0", 10)
	if len(tx.Hash) == 0 || tx.Hash == nil {
		return false, errors.New("hash is empty")
	}

	if len(tx.Data) > maxTransactionDataSizeBytes {
		return false, fmt.Errorf("data with size %d is greater than %d bytes", len(tx.Data), maxTransactionDataSizeBytes)
	}

	mainChain, err := hexutil.Decode(chainID)
	if err != nil {
		return false, fmt.Errorf("failed to decode chainID: %w", err)
	}

	if !bytes.Equal(tx.Chain, mainChain) {
		return false, errors.New("wrong chain")
	}

	if tx.From == "" {
		return false, errors.New("from is empty")
	}

	if tx.To == "" {
		return false, errors.New("to is empty")
	}

	if len(tx.Nounce) == 0 {
		return false, errors.New("nounce is empty")
	}

	if len(tx.PublicKey) == 0 {
		return false, errors.New("publicKey is empty")
	}

	if tx.TransactionFees == "" {
		return false, errors.New("transactionFees is empty")
	}

	if tx.Value == "" {
		return false, errors.New("value is empty")
	}

	val, err := hexutil.DecodeBig(tx.Value)
	if err != nil {
		return false, fmt.Errorf("value is malformed: %w", err)
	}

	if val.Cmp(zero) == -1 {
		return false, errors.New("value is negative")
	}

	valFees, err := hexutil.DecodeBig(tx.TransactionFees)
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

	if !bytes.Equal(tx.Hash, hash) {
		return false, errors.New("transaction is altered and doesn't match the hash")
	}

	newPubKey, err := ffgcrypto.PublicKeyFromBytes(tx.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to get publicKey: %w", err)
	}

	err = tx.VerifyWithPublicKey(newPubKey)
	if err != nil {
		return false, fmt.Errorf("failed to verify: %w", err)
	}

	fromAddr, err := ffgcrypto.RawPublicToAddress(tx.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to get address from publicKey: %w", err)
	}

	if tx.From != fromAddr {
		return false, errors.New("from address doesn't match the public key")
	}

	return true, nil
}

// ToProtoTransaction converts a transaction to protobuf message.
func ToProtoTransaction(tx Transaction) *ProtoTransaction {
	ptx := &ProtoTransaction{
		Hash:            make([]byte, len(tx.Hash)),
		Signature:       make([]byte, len(tx.Signature)),
		PublicKey:       make([]byte, len(tx.PublicKey)),
		Nounce:          make([]byte, len(tx.Nounce)),
		Data:            make([]byte, len(tx.Data)),
		From:            tx.From,
		To:              tx.To,
		Value:           tx.Value,
		TransactionFees: tx.TransactionFees,
		Chain:           make([]byte, len(tx.Chain)),
	}

	copy(ptx.Hash, tx.Hash)
	copy(ptx.Signature, tx.Signature)
	copy(ptx.PublicKey, tx.PublicKey)
	copy(ptx.Nounce, tx.Nounce)
	copy(ptx.Data, tx.Data)
	copy(ptx.Chain, tx.Chain)

	return ptx
}

// ProtoTransactionToTransaction returns a domain transaction from a protobuf message.
func ProtoTransactionToTransaction(ptx *ProtoTransaction) Transaction {
	tx := Transaction{
		Hash:            make([]byte, len(ptx.Hash)),
		Signature:       make([]byte, len(ptx.Signature)),
		PublicKey:       make([]byte, len(ptx.PublicKey)),
		Nounce:          make([]byte, len(ptx.Nounce)),
		Data:            make([]byte, len(ptx.Data)),
		From:            ptx.From,
		To:              ptx.To,
		Value:           ptx.Value,
		TransactionFees: ptx.TransactionFees,
		Chain:           make([]byte, len(ptx.Chain)),
	}

	copy(tx.Hash, ptx.Hash)
	copy(tx.Signature, ptx.Signature)
	copy(tx.PublicKey, ptx.PublicKey)
	copy(tx.Nounce, ptx.Nounce)
	copy(tx.Data, ptx.Data)
	copy(tx.Chain, ptx.Chain)

	return tx
}

// MarshalProtoTransaction serializes a block to a protobuf message.
func MarshalProtoTransaction(tx *ProtoTransaction) ([]byte, error) {
	txData, err := proto.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction: %w", err)
	}
	return txData, nil
}

// UnmarshalProtoBlock unserializes a byte array to a protobuf transaction.
func UnmarshalProtoBlock(data []byte) (*ProtoTransaction, error) {
	tx := ProtoTransaction{}
	if err := proto.Unmarshal(data, &tx); err != nil {
		return nil, fmt.Errorf("failed to unmarshal a transaction: %w", err)
	}
	return &tx, nil
}
