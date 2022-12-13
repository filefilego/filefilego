package transaction

import (
	"testing"

	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/filefilego/filefilego/internal/crypto"
	"github.com/stretchr/testify/assert"
)

func TestGetTransactionHash(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		tx     Transaction
		expErr string
	}{
		"invalid public key": {
			tx:     Transaction{},
			expErr: "publicKey is empty",
		},
		"invalid nounce": {
			tx: Transaction{
				PublicKey: []byte{12},
			},
			expErr: "nounce is empty",
		},
		"invalid from": {
			tx: Transaction{
				PublicKey: []byte{12},
				Nounce:    []byte{222},
			},
			expErr: "from is empty",
		},
		"invalid to": {
			tx: Transaction{
				PublicKey: []byte{12},
				Nounce:    []byte{222},
				From:      "0x0123",
			},
			expErr: "to is empty",
		},
		"invalid value": {
			tx: Transaction{
				PublicKey: []byte{12},
				Nounce:    []byte{222},
				From:      "0x0123",
				To:        "0x0123",
			},
			expErr: "value is empty",
		},
		"invalid transactionfees": {
			tx: Transaction{
				PublicKey: []byte{12},
				Nounce:    []byte{222},
				From:      "0x0123",
				To:        "0x0123",
				Value:     "0x123",
			},
			expErr: "transactionFees is empty",
		},
		"valid transaction": {
			tx: Transaction{
				PublicKey:       []byte{12},
				Nounce:          []byte{222},
				From:            "0x0123",
				To:              "0x0123",
				Value:           "0x123",
				TransactionFees: "0x33",
			},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			hash, err := tt.tx.GetTransactionHash()
			if tt.expErr != "" {
				assert.Nil(t, hash)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, hash)
			}
		})
	}
}

func TestSignAndVerifyTransaction(t *testing.T) {
	keypair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	publicKeyData, err := keypair.PublicKey.Raw()
	assert.NoError(t, err)
	tx := Transaction{
		PublicKey:       publicKeyData,
		Nounce:          []byte{1},
		From:            "0x0123",
		To:              "0x0123",
		Value:           "0x123",
		TransactionFees: "0x33",
	}

	assert.Empty(t, tx.Hash)
	assert.Empty(t, tx.Signature)
	// sign tx with private key
	err = tx.Sign(keypair.PrivateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, tx.Hash)
	assert.NotEmpty(t, tx.Signature)

	// veirfy with wrong public key
	keypair2, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	err = tx.VerifyWithPublicKey(keypair2.PublicKey)
	assert.EqualError(t, err, "failed verification of transaction")

	// verify tx with public key
	err = tx.VerifyWithPublicKey(keypair.PublicKey)
	assert.NoError(t, err)

	// remove sig from tx
	tx.Signature = []byte{}
	err = tx.VerifyWithPublicKey(keypair.PublicKey)
	assert.EqualError(t, err, "failed to verify transaction: malformed signature: too short: 0 < 8")
}

func TestValidate(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		when   func() *Transaction
		expErr string
	}{
		"empty hash": {
			expErr: "hash is empty",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.Hash = []byte{}
				return tx
			},
		},
		"data size is greater than defined": {
			expErr: "data with size 300001 is greater than 300000 bytes",
			when: func() *Transaction {
				tx := validTransaction(t)
				dt, _ := crypto.RandomEntropy(maxTransactionDataSizeBytes + 1)
				tx.Data = dt
				return tx
			},
		},
		"empty from": {
			expErr: "from is empty",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.From = ""
				return tx
			},
		},
		"empty to": {
			expErr: "to is empty",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.To = ""
				return tx
			},
		},
		"empty nounce": {
			expErr: "nounce is empty",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.Nounce = []byte{}
				return tx
			},
		},
		"empty publicKey": {
			expErr: "publicKey is empty",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.PublicKey = []byte{}
				return tx
			},
		},
		"empty transactionfees": {
			expErr: "transactionFees is empty",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.TransactionFees = ""
				return tx
			},
		},
		"empty value": {
			expErr: "value is empty",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.Value = ""
				return tx
			},
		},
		"malformed value": {
			expErr: "value is malformed: hex string without 0x prefix",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.Value = "_X1"
				return tx
			},
		},
		"malformed transactionFees": {
			expErr: "failed to decode transactionFees: hex string without 0x prefix",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.TransactionFees = "_X1"
				return tx
			},
		},
		"malformed publicKey": {
			expErr: "transaction is altered and doesn't match the hash",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.PublicKey = []byte{1}
				return tx
			},
		},
		"malformed from address": {
			expErr: "transaction is altered and doesn't match the hash",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.From = "0x12"
				return tx
			},
		},
		"success": {
			when: func() *Transaction {
				tx := validTransaction(t)
				return tx
			},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tx := tt.when()
			ok, err := tx.Validate()
			if tt.expErr != "" {
				assert.False(t, ok)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.True(t, ok)
			}
		})
	}
}

func TestProtoTransactionFunctions(t *testing.T) {
	tx := validTransaction(t)
	assert.NotNil(t, tx)
	ptx := ToProtoTransaction(*tx)
	assert.NotNil(t, ptx)
	derviedTx := ProtoTransactionToTransaction(ptx)
	assert.Equal(t, *tx, derviedTx)
}

func TestMarshalUnmarshalProtoTransaction(t *testing.T) {
	tx := validTransaction(t)
	assert.NotNil(t, tx)
	ptx := ToProtoTransaction(*tx)
	assert.NotNil(t, ptx)

	// marshal
	ptxData, err := MarshalProtoTransaction(ptx)
	assert.NoError(t, err)
	assert.NotNil(t, ptxData)

	// unmarshal
	derivedTx, err := UnmarshalProtoBlock(ptxData)
	assert.NoError(t, err)
	assert.NotNil(t, derivedTx)
	equalTransactions(ptx, derivedTx, t)
}

func equalTransactions(ptx, derivedTx *ProtoTransaction, t *testing.T) {
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

func validTransaction(t *testing.T) *Transaction {
	keypair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	pkyData, err := keypair.PublicKey.Raw()
	assert.NoError(t, err)

	mainChain, err := hexutil.Decode(chainID)
	assert.NoError(t, err)

	addr, err := crypto.RawPublicToAddress(pkyData)
	assert.NoError(t, err)

	tx := Transaction{
		PublicKey:       pkyData,
		Nounce:          []byte{1},
		Data:            []byte{1},
		From:            addr,
		To:              addr,
		Chain:           mainChain,
		Value:           "0x64",
		TransactionFees: "0x64",
	}
	err = tx.Sign(keypair.PrivateKey)
	assert.NoError(t, err)
	return &tx
}
