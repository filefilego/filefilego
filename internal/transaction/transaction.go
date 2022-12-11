package transaction

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/filefilego/filefilego/internal/common/hexutil"
	ffgcrypto "github.com/filefilego/filefilego/internal/crypto"
	"github.com/libp2p/go-libp2p/core/crypto"
)

const chainID = "0x01"
const maxTransactionDataSizeBytes = 300000

// Transaction represents a transaction.
type Transaction struct {
	// calculated after
	Hash      []byte
	Signature []byte

	// required
	PublickKey      []byte
	Nounce          []byte
	Data            []byte
	From            string
	To              string
	Value           string
	TransactionFees string
	Chain           []byte
}

// GetTransactionHash gets a hash of a transaction.
func (tx Transaction) GetTransactionHash() ([]byte, error) {
	mainChain, err := hexutil.Decode(chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode chainID: %w", err)
	}

	if len(tx.PublickKey) == 0 {
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
			tx.PublickKey,
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
	hash := sha256.Sum256(data)
	bts := hash[:]
	return bts, nil
}

// SignTransaction signs a transaction with a private key.
func (tx *Transaction) SignTransaction(key crypto.PrivKey) error {
	hash, err := tx.GetTransactionHash()
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

	if len(tx.PublickKey) == 0 {
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

	hash, err := tx.GetTransactionHash()
	if err != nil {
		return false, errors.New("failed to get transaction hash")
	}

	if !bytes.Equal(tx.Hash, hash) {
		return false, errors.New("transaction is altered and doesn't match the hash")
	}

	newPubKey, err := ffgcrypto.PublicKeyFromBytes(tx.PublickKey)
	if err != nil {
		return false, fmt.Errorf("failed to get publicKey: %w", err)
	}

	err = tx.VerifyWithPublicKey(newPubKey)
	if err != nil {
		return false, fmt.Errorf("failed to verify: %w", err)
	}

	fromAddr, err := ffgcrypto.RawPublicToAddress(tx.PublickKey)
	if err != nil {
		return false, fmt.Errorf("failed to get address from publicKey: %w", err)
	}

	if tx.From != fromAddr {
		return false, errors.New("from address doesn't match the public key")
	}

	return true, nil
}
