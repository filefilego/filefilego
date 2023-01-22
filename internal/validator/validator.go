package validator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sort"

	"github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/blockchain"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	ffgcrypto "github.com/filefilego/filefilego/internal/crypto"
	"github.com/filefilego/filefilego/internal/transaction"
	"github.com/libp2p/go-libp2p/core/crypto"
)

// NetworkMessagePublisher is a pub sub message broadcaster.
type NetworkMessagePublisher interface {
	PublishMessageToNetwork(ctx context.Context, data []byte) error
}

// Validator struct.
type Validator struct {
	node       NetworkMessagePublisher
	blockchain blockchain.Interface
	privateKey crypto.PrivKey

	address string
}

// New constructs a new validator.
func New(node NetworkMessagePublisher, bchain blockchain.Interface, privateKey crypto.PrivKey) (*Validator, error) {
	if node == nil {
		return nil, errors.New("node is nil")
	}

	if bchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	if privateKey == nil {
		return nil, errors.New("privateKey is nil")
	}

	rawPubKey, err := privateKey.GetPublic().Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key bytes: %w", err)
	}

	verifierAddr, err := ffgcrypto.RawPublicToAddress(rawPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get address from public key: %w", err)
	}

	isVerifier := false
	for _, verifier := range block.BlockVerifiers {
		if verifier.Address == verifierAddr {
			isVerifier = true
			break
		}
	}

	if !isVerifier {
		return nil, errors.New("validator key is not a verifier")
	}

	return &Validator{
		node:       node,
		blockchain: bchain,
		privateKey: privateKey,
		address:    verifierAddr,
	}, nil
}

// SealBroadcastBlock seals and broadcast the block to the network.
func (m *Validator) SealBroadcastBlock() error {
	mainChain, err := hexutil.Decode(transaction.ChainID)
	if err != nil {
		return fmt.Errorf("failed to decode chainID: %w", err)
	}

	publicKeyBytes, err := m.privateKey.GetPublic().Raw()
	if err != nil {
		return fmt.Errorf("failed to get public key bytes: %w", err)
	}

	currentBlockHeight := m.blockchain.GetHeight()
	blockReward, err := block.GetReward(currentBlockHeight + 1)
	if err != nil {
		return fmt.Errorf("failed to get block reward: %w", err)
	}

	addrBytes, err := ffgcrypto.RawPublicToAddressBytes(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to get byte address from public key: %w", err)
	}

	nounce := m.blockchain.GetNounceFromMemPool(addrBytes)
	nounceBytes := big.NewInt(0).SetUint64(nounce + 1).Bytes()

	coinbaseTx := transaction.Transaction{
		PublicKey:       make([]byte, len(publicKeyBytes)),
		Nounce:          make([]byte, len(nounceBytes)),
		From:            m.address,
		To:              m.address,
		Value:           hexutil.EncodeBig(blockReward),
		TransactionFees: "0x0",
		Chain:           mainChain,
	}
	copy(coinbaseTx.PublicKey, publicKeyBytes)
	copy(coinbaseTx.Nounce, nounceBytes)

	err = coinbaseTx.Sign(m.privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign coinbase transaction: %w", err)
	}
	mempoolTransactions := m.blockchain.GetTransactionsFromPool()
	mempoolTransactions = prependTransaction(mempoolTransactions, coinbaseTx)

	log.Println(mempoolTransactions)

	return nil
}

func prependTransaction(x []transaction.Transaction, y transaction.Transaction) []transaction.Transaction {
	x = append(x, transaction.Transaction{})
	copy(x[1:], x)
	x[0] = y
	return x
}

func sortTransactionsByNounce(transactions []transaction.Transaction) []transaction.Transaction {
	sort.Slice(transactions, func(i, j int) bool {
		first := hexutil.DecodeBigFromBytesToUint64(transactions[i].Nounce)
		second := hexutil.DecodeBigFromBytesToUint64(transactions[j].Nounce)

		return first < second
	})
	return transactions
}
