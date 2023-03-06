package block

import (
	"testing"
	"time"

	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
	transaction "github.com/filefilego/filefilego/transaction"
	"github.com/stretchr/testify/assert"
)

func TestGetBlockHash(t *testing.T) {
	t.Parallel()
	validBlock, _ := validBlock(t)
	cases := map[string]struct {
		block  Block
		expErr string
	}{
		"empty merkle": {
			block:  Block{},
			expErr: "merkle root hash is empty",
		},
		"valid block": {
			block: *validBlock,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// get merkle hash for valid block because its needed
			if tt.expErr == "" {
				merkleHash, _ := tt.block.GetMerkleHash()
				tt.block.MerkleHash = merkleHash
			}
			hash, err := tt.block.GetBlockHash()
			if tt.expErr != "" {
				assert.Nil(t, hash)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, hash)
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetMerkleHashGetBlockHash(t *testing.T) {
	t.Parallel()
	validBlock, _ := validBlock(t)
	cases := map[string]struct {
		block  Block
		expErr string
	}{
		"no transactions in the block": {
			block:  Block{},
			expErr: "no transactions to hash",
		},
		"valid block": {
			block: *validBlock,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mhash, err := tt.block.GetMerkleHash()
			if tt.expErr != "" {
				assert.Nil(t, mhash)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, mhash)
			}
		})
	}
}

func TestSignAndVerifyBlock(t *testing.T) {
	block, keypair := validBlock(t)
	assert.NotNil(t, block)

	assert.Empty(t, block.Hash)
	assert.Empty(t, block.Signature)

	// sign block
	err := block.Sign(keypair.PrivateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, block.Hash)
	assert.NotEmpty(t, block.Signature)
	err = block.VerifyWithPublicKey(keypair.PublicKey)
	assert.NoError(t, err)

	// sign an invalid block
	block2, _ := validBlock(t)
	block2.Transactions = nil
	err = block2.Sign(keypair.PrivateKey)
	assert.EqualError(t, err, "failed to get block's merkle hash: no transactions to hash")
}

func TestGetCoinbaseTransaction(t *testing.T) {
	block, keypair := validBlock(t)
	assert.NotNil(t, block)
	err := block.Sign(keypair.PrivateKey)
	assert.NoError(t, err)

	// get the coinbase tx and compare it to the one in the block
	tx, err := block.GetAndValidateCoinbaseTransaction()
	assert.NoError(t, err)
	assert.Equal(t, tx, block.Transactions[0])

	// invalidate the public key data from the coinbase tx
	block.Transactions[0].PublicKey = []byte{}
	_, err = block.GetAndValidateCoinbaseTransaction()
	assert.EqualError(t, err, "failed to derive public key from transaction: malformed public key: invalid length: 0")

	// invalid coinabse
	block.Transactions = nil
	_, err = block.GetAndValidateCoinbaseTransaction()
	assert.EqualError(t, err, "no transactions in block")

	// different block signer with coinbase signer
	block2, _ := validBlock(t)
	err = block2.Sign(keypair.PrivateKey)
	assert.NoError(t, err)
	_, err = block2.GetAndValidateCoinbaseTransaction()
	assert.EqualError(t, err, "coinbase transaction signer doesn't match the block signer: failed verification of block")
}

func TestValidate(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		when   func() (*Block, crypto.KeyPair)
		expErr string
	}{
		"empty hash": {
			expErr: "hash is empty",
			when: func() (*Block, crypto.KeyPair) {
				block, kp := validBlock(t)
				err := block.Sign(kp.PrivateKey)
				if err != nil {
					return nil, kp
				}
				block.Hash = []byte{}
				return block, kp
			},
		},
		"empty merkle hash": {
			expErr: "merkle hash is empty",
			when: func() (*Block, crypto.KeyPair) {
				block, kp := validBlock(t)
				err := block.Sign(kp.PrivateKey)
				if err != nil {
					return nil, kp
				}
				block.MerkleHash = []byte{}
				return block, kp
			},
		},
		"empty previous block hash": {
			expErr: "previousBlockHash is empty",
			when: func() (*Block, crypto.KeyPair) {
				block, kp := validBlock(t)
				err := block.Sign(kp.PrivateKey)
				if err != nil {
					return nil, kp
				}
				block.PreviousBlockHash = []byte{}
				return block, kp
			},
		},
		"invalid timestamp": {
			expErr: "timestamp is empty",
			when: func() (*Block, crypto.KeyPair) {
				block, kp := validBlock(t)
				err := block.Sign(kp.PrivateKey)
				if err != nil {
					return nil, kp
				}
				block.Timestamp = -1
				return block, kp
			},
		},
		"empty transactions": {
			expErr: "block doesn't contain any transaction",
			when: func() (*Block, crypto.KeyPair) {
				block, kp := validBlock(t)
				err := block.Sign(kp.PrivateKey)
				if err != nil {
					return nil, kp
				}
				block.Transactions = []transaction.Transaction{}
				return block, kp
			},
		},
		"block data exceeds max size": {
			expErr: "data with size 300001 is greater than 300000 bytes",
			when: func() (*Block, crypto.KeyPair) {
				block, kp := validBlock(t)
				err := block.Sign(kp.PrivateKey)
				if err != nil {
					return nil, kp
				}
				bts, _ := crypto.RandomEntropy(maxBlockDataSizeBytes + 1)
				block.Data = bts
				return block, kp
			},
		},
		"modified hash": {
			expErr: "failed to get coinbase transaction: coinbase transaction signer doesn't match the block signer: failed verification of block",
			when: func() (*Block, crypto.KeyPair) {
				block, kp := validBlock(t)
				err := block.Sign(kp.PrivateKey)
				if err != nil {
					return nil, kp
				}
				bts, _ := crypto.RandomEntropy(32)
				block.Hash = bts
				return block, kp
			},
		},
		"wrong coinbase transaction": {
			expErr: "failed to get coinbase transaction: failed to derive public key from transaction: malformed public key: invalid length: 0",
			when: func() (*Block, crypto.KeyPair) {
				block, kp := validBlock(t)
				err := block.Sign(kp.PrivateKey)
				if err != nil {
					return nil, kp
				}
				block.Transactions[0].PublicKey = []byte{}
				return block, kp
			},
		},
		"success": {
			when: func() (*Block, crypto.KeyPair) {
				block, kp := validBlock(t)
				// add the current kp to verifiers list
				SetBlockVerifiers(Verifier{Address: kp.Address})
				err := block.Sign(kp.PrivateKey)
				if err != nil {
					return nil, kp
				}
				return block, kp
			},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			b, _ := tt.when()
			ok, err := b.Validate()
			if tt.expErr != "" {
				assert.False(t, ok)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.True(t, ok)
				assert.NoError(t, err)
			}
		})
	}
}

func TestMarshalUnmarshalProtoBlock(t *testing.T) {
	block, _ := validBlock(t)
	assert.NotNil(t, block)
	pblock := ToProtoBlock(*block)
	assert.NotNil(t, pblock)

	data, err := MarshalProtoBlock(pblock)
	assert.NoError(t, err)
	assert.NotNil(t, data)

	derivedBlock, err := UnmarshalProtoBlock(data)
	assert.NoError(t, err)
	assert.NotNil(t, derivedBlock)

	assert.Equal(t, pblock.Number, derivedBlock.Number)
	assert.Equal(t, pblock.Timestamp, derivedBlock.Timestamp)

	assert.ElementsMatch(t, pblock.Data, derivedBlock.Data)
	assert.ElementsMatch(t, pblock.Hash, derivedBlock.Hash)
	assert.ElementsMatch(t, pblock.MerkleHash, derivedBlock.MerkleHash)
	assert.ElementsMatch(t, pblock.PreviousBlockHash, derivedBlock.PreviousBlockHash)
	assert.ElementsMatch(t, pblock.Signature, derivedBlock.Signature)

	for i := range derivedBlock.Transactions {
		equalTransactions(pblock.Transactions[i], derivedBlock.Transactions[i], t)
	}
}

func TestProtoBlockMethods(t *testing.T) {
	block, kp := validBlock(t)
	err := block.Sign(kp.PrivateKey)
	assert.NoError(t, err)
	assert.NotNil(t, block)

	protoBlock := ToProtoBlock(*block)
	assert.NotNil(t, protoBlock)

	derivedBlock := ProtoBlockToBlock(protoBlock)
	assert.Equal(t, *block, derivedBlock)
}

func equalTransactions(ptx, derivedTx *transaction.ProtoTransaction, t *testing.T) {
	assert.ElementsMatch(t, ptx.Data, derivedTx.Data)
	assert.ElementsMatch(t, ptx.Hash, derivedTx.Hash)
	assert.ElementsMatch(t, ptx.Signature, derivedTx.Signature)
	assert.ElementsMatch(t, ptx.Nounce, derivedTx.Nounce)
	assert.ElementsMatch(t, ptx.PublicKey, derivedTx.PublicKey)
	assert.ElementsMatch(t, ptx.Chain, derivedTx.Chain)

	assert.Equal(t, ptx.From, derivedTx.From)
	assert.Equal(t, ptx.To, derivedTx.To)
	assert.Equal(t, ptx.Value, derivedTx.Value)
	assert.Equal(t, ptx.TransactionFees, derivedTx.TransactionFees)
}

// generate a block and propagate the keypair used for the tx
func validBlock(t *testing.T) (*Block, crypto.KeyPair) {
	validTx, kp := validTransaction(t)
	b := Block{
		Timestamp:         time.Now().Unix(),
		Data:              []byte{1},
		PreviousBlockHash: []byte{1, 1},
		Transactions: []transaction.Transaction{
			// its a coinbase tx
			*validTx,
		},
		Number: 0,
	}

	return &b, kp
}

// generate a keypair and use it to sign tx
func validTransaction(t *testing.T) (*transaction.Transaction, crypto.KeyPair) {
	keypair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	pkyData, err := keypair.PublicKey.Raw()
	assert.NoError(t, err)

	mainChain, err := hexutil.Decode("0x01")
	assert.NoError(t, err)

	addr, err := crypto.RawPublicToAddress(pkyData)
	assert.NoError(t, err)

	tx := transaction.Transaction{
		PublicKey:       pkyData,
		Nounce:          []byte{0},
		Data:            []byte{1},
		From:            addr,
		To:              addr,
		Chain:           mainChain,
		Value:           "0x22b1c8c1227a00000",
		TransactionFees: "0x0",
	}
	err = tx.Sign(keypair.PrivateKey)
	assert.NoError(t, err)
	return &tx, keypair
}
