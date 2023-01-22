package validator

import (
	"testing"

	"github.com/filefilego/filefilego/internal/block"
	"github.com/filefilego/filefilego/internal/blockchain"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/filefilego/filefilego/internal/keystore"
	"github.com/filefilego/filefilego/internal/node"
	"github.com/filefilego/filefilego/internal/transaction"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	t.Parallel()
	kp, err := keystore.NewKey()
	assert.NoError(t, err)
	pubKeyBytes, err := kp.PublicKey.Raw()
	assert.NoError(t, err)
	block.BlockVerifiers = append(block.BlockVerifiers, block.Verifier{
		Address:   kp.Address,
		PublicKey: hexutil.Encode(pubKeyBytes),
	})

	cases := map[string]struct {
		node       NetworkMessagePublisher
		blockchain blockchain.Interface
		privateKey crypto.PrivKey
		expErr     string
	}{
		"empty node": {
			expErr: "node is nil",
		},
		"empty blockchain": {
			node:   &node.Node{},
			expErr: "blockchain is nil",
		},
		"empty privateKey": {
			node:       &node.Node{},
			blockchain: &blockchain.Blockchain{},
			expErr:     "privateKey is nil",
		},
		"success": {
			node:       &node.Node{},
			blockchain: &blockchain.Blockchain{},
			privateKey: kp.PrivateKey,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			miner, err := New(tt.node, tt.blockchain, tt.privateKey)
			if tt.expErr != "" {
				assert.Nil(t, miner)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, miner)
				assert.NoError(t, err)
			}
		})
	}
}

func TestSortTransactionsByNounce(t *testing.T) {
	transactions := []transaction.Transaction{
		{
			From:   "0x1",
			Nounce: []byte{1},
		},
		{
			From:   "0x2",
			Nounce: []byte{5},
		},
		{
			From:   "0x1",
			Nounce: []byte{3},
		},
		{
			From:   "0x2",
			Nounce: []byte{4},
		},
		{
			From:   "0x1",
			Nounce: []byte{2},
		},
	}

	sorted := sortTransactionsByNounce(transactions)
	assert.Len(t, sorted, 5)
	assert.Equal(t, []byte{1}, sorted[0].Nounce)
	assert.Equal(t, []byte{2}, sorted[1].Nounce)
	assert.Equal(t, []byte{3}, sorted[2].Nounce)
	assert.Equal(t, []byte{4}, sorted[3].Nounce)
	assert.Equal(t, []byte{5}, sorted[4].Nounce)
}
