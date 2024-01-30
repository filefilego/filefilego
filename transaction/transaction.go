package transaction

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/cbergoon/merkletree"
	ethcommon "github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/filefilego/filefilego/common/hexutil"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
	"github.com/libp2p/go-libp2p/core/crypto"
)

// ChainID represents the main-net chain id.
const ChainID = "0x01"

// ChainIDGlobal is the global evm compatible chain id.
const ChainIDGlobal = 191

// ChainIDGlobalHex
const ChainIDGlobalHex = "0xbf"

const gasLimit = 21000

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
	// gasPrice string
}

// NewTransaction constructs a new transaction.
func NewTransaction(txType uint8, publicKey, nounce, data []byte, from, to, value, transactionFees string, chain []byte) *Transaction {
	tx := &Transaction{
		publicKey:       make([]byte, len(publicKey)),
		nounce:          make([]byte, len(nounce)),
		data:            make([]byte, len(data)),
		from:            from,
		to:              to,
		value:           value,
		transactionFees: transactionFees,
		chain:           make([]byte, len(chain)),
		txType:          txType,
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

func (tx *Transaction) Type() uint8 {
	return tx.txType
}

func ParseEth(rawTX string) (*Transaction, error) {
	var ethTx ethTypes.Transaction
	txData, err := hexutil.DecodeNoPrefix(rawTX)
	if err != nil {
		return nil, fmt.Errorf("failed to decode transaction: %w", err)
	}

	if err := ethTx.UnmarshalBinary(txData); err != nil {
		return nil, fmt.Errorf("failed to decode typed transaction: %w", err)
	}

	v, r, s := ethTx.RawSignatureValues()
	hash := ethTx.Hash()

	signatureRS := append(r.Bytes(), s.Bytes()...)
	signature := append(r.Bytes(), s.Bytes()...)

	// v = chain_id * 2 + 35 + recovery_id
	tmp := big.NewInt(0).Set(v)
	recoveryID := tmp.Sub(tmp, big.NewInt(ChainIDGlobal*2+35))

	if recoveryID.Cmp(big.NewInt(0)) == 0 {
		signature = append(signature, []byte{0}...)
	} else {
		signature = append(signature, []byte{1}...)
	}

	pubkeyData, err := ethcrypto.Ecrecover(hash.Bytes(), signature)
	if err != nil {
		return nil, fmt.Errorf("failed to recover public key: %v", err)
	}

	verified := ethcrypto.VerifySignature(pubkeyData, hash.Bytes(), signatureRS)
	if !verified {
		return nil, errors.New("failed to verify transaction")
	}

	from, err := ethTypes.Sender(ethTypes.NewCancunSigner(big.NewInt(ChainIDGlobal)), &ethTx)
	if err != nil {
		return nil, fmt.Errorf("failed to recover from address: %v", err)
	}

	nounce := big.NewInt(0).SetUint64(ethTx.Nonce()).Bytes()
	if len(nounce) == 0 {
		nounce = []byte{0}
	}

	tx := &Transaction{
		txType:    EthTxType,
		hash:      ethTx.Hash().Bytes(),
		signature: signature,

		// publicKey can be derived
		// we keep it empty to save disk space
		publicKey:       []byte{},
		nounce:          nounce,
		data:            ethTx.Data(),
		from:            from.Hex(),
		to:              ethTx.To().Hex(),
		value:           "0x" + ethTx.Value().Text(16),
		transactionFees: "0x" + ethTx.GasPrice().Text(16),
		chain:           ethTx.ChainId().Bytes(),
	}

	return tx, nil
}

// serialize the transaction to bytes.
func (tx *Transaction) serialize() ([]byte, error) {
	whichChain := ChainIDGlobalHex
	if tx.txType == LegacyTxType {
		whichChain = ChainID
		if len(tx.publicKey) == 0 {
			return nil, errors.New("publicKey is empty")
		}

		if tx.from == "" {
			return nil, errors.New("from is empty")
		}
	}

	mainChain, err := hexutil.Decode(whichChain)
	if err != nil {
		return nil, fmt.Errorf("failed to decode chainID: %w", err)
	}

	if len(tx.nounce) == 0 {
		return nil, errors.New("nounce is empty")
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
	return tx.getHash()
}

// getHash gets a hash of a transaction.
func (tx *Transaction) getHash() ([]byte, error) {
	data, err := tx.serialize()
	if err != nil {
		return nil, err
	}

	// eth
	if tx.txType == EthTxType {
		nounce := big.NewInt(0).SetBytes(tx.nounce).Uint64()
		to := ethcommon.HexToAddress(tx.to)
		value, err := hexutil.DecodeBig(tx.value)
		if err != nil {
			return nil, fmt.Errorf("failed to decode value: %v", err)
		}

		transactionFees, err := hexutil.DecodeBig(tx.transactionFees)
		if err != nil {
			return nil, fmt.Errorf("failed to decode transactionFees: %v", err)
		}

		if len(tx.signature) != 65 {
			return nil, fmt.Errorf("signature must be 65 bytes but got %d", len(tx.signature))
		}

		r := big.NewInt(0).SetBytes(tx.signature[0:32])
		s := big.NewInt(0).SetBytes(tx.signature[32:64])
		vByte := tx.signature[64]
		v := big.NewInt(int64(ChainIDGlobal*2 + 35 + int(vByte)))

		ethTx := ethTypes.NewTx(&ethTypes.LegacyTx{
			Nonce:    nounce,
			GasPrice: transactionFees,
			Gas:      gasLimit,
			To:       &to,
			Value:    value,
			Data:     tx.Data(),
			V:        v,
			R:        r,
			S:        s,
		})

		// Serialize the transaction using RLP encoding
		rlpEncodedTx, err := rlp.EncodeToBytes(ethTx)
		if err != nil {
			return nil, fmt.Errorf("failed to encode transaction data: %v", err)
		}

		// Hash the RLP encoded transaction using Keccak-256
		txHash := ethcrypto.Keccak256(rlpEncodedTx)

		// ethTx := ethTypes.NewTx(&ethTypes.AccessListTx{
		// 	ChainID:  big.NewInt(ChainIDGlobal),
		// 	Nonce:    nounce,
		// 	GasPrice: transactionFees,
		// 	Gas:      gasLimit,
		// 	To:       &to,
		// 	Value:    value,
		// 	Data:     tx.Data(),
		// })

		// ethTx := ethTypes.NewTransaction(nounce, to, value, gasLimit, transactionFees, tx.data)
		// hashedData := ethTypes.NewLondonSigner(big.NewInt(ChainIDGlobal)).Hash(ethTx).Bytes()
		return txHash, nil
	}

	// ffg
	h := sha256.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Equals tests for equality of two Contents.
func (tx *Transaction) Equals(other merkletree.Content) (bool, error) {
	if tx.txType == EthTxType {
		thisTx, err := tx.getHash()
		if err != nil {
			return false, err
		}

		otherTx, err := other.(*Transaction).getHash()
		if err != nil {
			return false, err
		}

		return bytes.Equal(thisTx, otherTx), nil
	}

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
	hash, err := tx.getHash()
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

	hash, err := tx.getHash()
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
		TxType:          TxType(tx.txType),
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
		txType:          uint8(ptx.TxType),
	}

	copy(tx.hash, ptx.Hash)
	copy(tx.signature, ptx.Signature)
	copy(tx.publicKey, ptx.PublicKey)
	copy(tx.nounce, ptx.Nounce)
	copy(tx.data, ptx.Data)
	copy(tx.chain, ptx.Chain)

	return tx
}
