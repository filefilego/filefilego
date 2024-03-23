package validator

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	"github.com/filefilego/filefilego/block"
	"github.com/filefilego/filefilego/blockchain"
	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/common/hexutil"
	ffgcrypto "github.com/filefilego/filefilego/crypto"
	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/filefilego/filefilego/transaction"
	"github.com/libp2p/go-libp2p/core/crypto"
)

// NetworkMessagePublisher is a pub sub message broadcaster.
type NetworkMessagePublisher interface {
	PublishMessageToNetwork(ctx context.Context, topicName string, data []byte) error
}

// Validator struct.
type Validator struct {
	node        NetworkMessagePublisher
	blockchain  blockchain.Interface
	privateKeys []crypto.PrivKey
	idx         int
	mu          sync.Mutex
	address     []string
}

// New constructs a new validator.
func New(node NetworkMessagePublisher, bchain blockchain.Interface, privateKeys []crypto.PrivKey) (*Validator, error) {
	if node == nil {
		return nil, errors.New("node is nil")
	}

	if bchain == nil {
		return nil, errors.New("blockchain is nil")
	}

	if len(privateKeys) == 0 {
		return nil, errors.New("privateKeys is empty")
	}

	v := &Validator{
		node:        node,
		blockchain:  bchain,
		privateKeys: make([]crypto.PrivKey, 0),
		address:     make([]string, 0),
	}

	for _, privateKey := range privateKeys {
		rawPubKey, err := privateKey.GetPublic().Raw()
		if err != nil {
			return nil, fmt.Errorf("failed to get public key bytes: %w", err)
		}

		verifierAddr, err := ffgcrypto.RawPublicToAddress(rawPubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get address from public key: %w", err)
		}

		isVerifier := false
		allVerifiers := block.GetBlockVerifiers()
		for _, verifier := range allVerifiers {
			if verifier.Address == verifierAddr {
				isVerifier = true
				break
			}
		}

		if !isVerifier {
			return nil, errors.New("validator key is not a verifier")
		}

		v.privateKeys = append(v.privateKeys, privateKey)
		v.address = append(v.address, verifierAddr)
	}

	return v, nil
}

func (m *Validator) getPK() (crypto.PrivKey, string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	k := m.privateKeys[m.idx]
	add := m.address[m.idx]
	m.idx = (m.idx + 1) % len(m.privateKeys)

	return k, add
}

func (m *Validator) prepareMempoolTransactions() []transaction.Transaction {
	balances := NewUncommitedBalance()
	mempoolTransactions := m.blockchain.GetTransactionsFromPool()
	mempoolTransactions = sortTransactionsByNounce(mempoolTransactions)

	// set the uncommitted balances of addresses
	for _, tx := range mempoolTransactions {
		fromBytes, err := hexutil.Decode(tx.From())
		if err != nil {
			log.Errorf("failed to decode from field from transaction: %v", err)
			continue
		}

		// prevent getting state for addresses which we already retrieved
		if balances.IsInitialized(tx.From()) {
			continue
		}

		state, err := m.blockchain.GetAddressState(fromBytes)
		if err != nil {
			// TODO: remove them from mempool, also handle for the below cases
			log.Errorf("failed to get address state of %s : %v", tx.From(), err)
			continue
		}

		balanceFrom, err := state.GetBalance()
		if err != nil {
			log.Errorf("failed to get address balance of %s : %v", tx.From(), err)
			continue
		}

		nounceFrom, err := state.GetNounce()
		if err != nil {
			log.Errorf("failed to get address nounce of %s : %v", tx.From(), err)
			continue
		}

		balances.InitializeBalanceAndNounceFor(tx.From(), balanceFrom, nounceFrom)
	}

	// we have the balances, go through the transactions again and see which are allowed
	validatedTransaction := make([]transaction.Transaction, 0)
	for _, tx := range mempoolTransactions {
		amount, err := hexutil.DecodeBig(tx.Value())
		if err != nil {
			continue
		}
		transactionFees, err := hexutil.DecodeBig(tx.TransactionFees())
		if err != nil {
			continue
		}
		amount = amount.Add(amount, transactionFees)
		ok := balances.Subtract(tx.From(), amount, hexutil.DecodeBigFromBytesToUint64(tx.Nounce()))
		if ok {
			validatedTransaction = append(validatedTransaction, tx)
		}
	}

	return validatedTransaction
}

func (m *Validator) getCoinbaseTX(pk crypto.PrivKey, address string) (*transaction.Transaction, error) {
	mainChain, err := hexutil.Decode(transaction.ChainID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode chainID: %w", err)
	}

	publicKeyBytes, err := pk.GetPublic().Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key bytes: %w", err)
	}

	currentBlockHeight := m.blockchain.GetHeight()
	blockReward, err := block.GetReward(currentBlockHeight + 1)
	if err != nil {
		return nil, fmt.Errorf("failed to get block reward: %w", err)
	}

	coinbaseTx := transaction.NewTransaction(transaction.LegacyTxType, publicKeyBytes, []byte{0}, []byte{}, address, address, hexutil.EncodeBig(blockReward), "0x0", mainChain)

	err = coinbaseTx.Sign(pk)
	if err != nil {
		return nil, fmt.Errorf("failed to sign coinbase transaction: %w", err)
	}
	return coinbaseTx, nil
}

// BroadcastBlock broadcasts a block to the network.
func (m *Validator) BroadcastBlock(ctx context.Context, validBlock *block.Block) error {
	payload := messages.GossipPayload{
		Message: &messages.GossipPayload_Blocks{Blocks: &messages.ProtoBlocks{Blocks: []*block.ProtoBlock{block.ToProtoBlock(*validBlock)}}},
	}
	blockData, err := proto.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("failed to marshal proto block: %w", err)
	}
	err = m.node.PublishMessageToNetwork(ctx, common.FFGNetPubSubBlocksTXQuery, blockData)
	if err != nil {
		return fmt.Errorf("failed to publish block to the network: %w", err)
	}
	return nil
}

// SealBlock seals a block.
func (m *Validator) SealBlock(timestamp int64) (*block.Block, string, error) {
	pk, addr := m.getPK()
	coinbaseTX, err := m.getCoinbaseTX(pk, addr)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get coinbase transaction: %w", err)
	}
	mempoolTransactions := m.prepareMempoolTransactions()
	mempoolTransactions = prependTransaction(mempoolTransactions, *coinbaseTX)

	lastBlockHash := m.blockchain.GetLastBlockHash()
	if lastBlockHash == nil {
		return nil, "", errors.New("failed to get last block hash from db")
	}

	block := block.Block{
		Timestamp:         timestamp,
		PreviousBlockHash: lastBlockHash,
		Transactions:      mempoolTransactions,
		Number:            m.blockchain.GetHeight() + 1,
	}

	err = block.Sign(pk)
	if err != nil {
		return nil, "", fmt.Errorf("failed to sign block: %w", err)
	}

	err = m.blockchain.PerformStateUpdateFromBlock(block)
	if err != nil {
		return nil, "", fmt.Errorf("failed to update blockchain: %w", err)
	}

	return &block, addr, nil
}

func prependTransaction(x []transaction.Transaction, y transaction.Transaction) []transaction.Transaction {
	x = append(x, transaction.Transaction{})
	copy(x[1:], x)
	x[0] = y
	return x
}

func sortTransactionsByNounce(transactions []transaction.Transaction) []transaction.Transaction {
	sort.Slice(transactions, func(i, j int) bool {
		first := hexutil.DecodeBigFromBytesToUint64(transactions[i].Nounce())
		second := hexutil.DecodeBigFromBytesToUint64(transactions[j].Nounce())

		return first < second
	})
	return transactions
}
