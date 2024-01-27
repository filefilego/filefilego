package transaction

import (
	"testing"

	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
	"github.com/stretchr/testify/assert"
)

// {"type":"0x0","chainId":"0xbf","nonce":"0x0","to":"0xb000e8bbf1fa6b3391802393d8200b5936cf56f6","gas":"0x5208","gasPrice":"0x3e8","maxPriorityFeePerGas":null,"maxFeePerGas":null,"value":"0x989680","input":"0x","v":"0x1a1","r":"0xa154e401962ae5135763bd348780a114b8564b83d46494d1d1ec6ff7cd1d6326","s":"0x5c2662275ebc59ab44fd7c671c1e90ab99c090cc7d09a6b3d83e457b5dd9d88c","hash":"0x56ac5faa78cb9efc2bc677281252a9ff8e927b3c6b9cf825487253eb63b50c2b"}

func TestEthCompatibleTx(t *testing.T) {
	tx, err := NewEthTX("f866808203e882520894b000e8bbf1fa6b3391802393d8200b5936cf56f683989680808201a1a0a154e401962ae5135763bd348780a114b8564b83d46494d1d1ec6ff7cd1d6326a05c2662275ebc59ab44fd7c671c1e90ab99c090cc7d09a6b3d83e457b5dd9d88c")
	assert.NoError(t, err)
	assert.NotNil(t, tx)
}

func TestCalculateHash(t *testing.T) {
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
				publicKey: []byte{12},
			},
			expErr: "nounce is empty",
		},
		"invalid from": {
			tx: Transaction{
				publicKey: []byte{12},
				nounce:    []byte{222},
			},
			expErr: "from is empty",
		},
		"invalid to": {
			tx: Transaction{
				publicKey: []byte{12},
				nounce:    []byte{222},
				from:      "0x0123",
			},
			expErr: "to is empty",
		},
		"invalid value": {
			tx: Transaction{
				publicKey: []byte{12},
				nounce:    []byte{222},
				from:      "0x0123",
				to:        "0x0123",
			},
			expErr: "value is empty",
		},
		"invalid transactionfees": {
			tx: Transaction{
				publicKey: []byte{12},
				nounce:    []byte{222},
				from:      "0x0123",
				to:        "0x0123",
				value:     "0x123",
			},
			expErr: "transactionFees is empty",
		},
		"valid transaction": {
			tx: Transaction{
				publicKey:       []byte{12},
				nounce:          []byte{222},
				from:            "0x0123",
				to:              "0x0123",
				value:           "0x123",
				transactionFees: "0x33",
			},
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			hash, err := tt.tx.CalculateHash()
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
		publicKey:       publicKeyData,
		nounce:          []byte{0},
		from:            "0x0123",
		to:              "0x0123",
		value:           "0x123",
		transactionFees: "0x33",
	}

	assert.Empty(t, tx.hash)
	assert.Empty(t, tx.signature)
	// sign tx with private key
	err = tx.Sign(keypair.PrivateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, tx.hash)
	assert.NotEmpty(t, tx.signature)

	// veirfy with wrong public key
	keypair2, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	err = tx.VerifyWithPublicKey(keypair2.PublicKey)
	assert.EqualError(t, err, "failed verification of transaction")

	// verify tx with public key
	err = tx.VerifyWithPublicKey(keypair.PublicKey)
	assert.NoError(t, err)

	// remove sig from tx
	tx.signature = []byte{}
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
				tx.hash = []byte{}
				return tx
			},
		},
		"data size is greater than defined": {
			expErr: "data with size 300001 is greater than 300000 bytes",
			when: func() *Transaction {
				tx := validTransaction(t)
				dt, _ := crypto.RandomEntropy(maxTransactionDataSizeBytes + 1)
				tx.data = dt
				return tx
			},
		},
		"empty from": {
			expErr: "from is empty",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.from = ""
				return tx
			},
		},
		"empty to": {
			expErr: "to is empty",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.to = ""
				return tx
			},
		},
		"empty nounce": {
			expErr: "nounce is empty",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.nounce = []byte{}
				return tx
			},
		},
		"empty publicKey": {
			expErr: "publicKey is empty",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.publicKey = []byte{}
				return tx
			},
		},
		"empty transactionfees": {
			expErr: "transactionFees is empty",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.transactionFees = ""
				return tx
			},
		},
		"empty value": {
			expErr: "value is empty",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.value = ""
				return tx
			},
		},
		"malformed value": {
			expErr: "value is malformed: hex string without 0x prefix",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.value = "_X1"
				return tx
			},
		},
		"malformed transactionFees": {
			expErr: "failed to decode transactionFees: hex string without 0x prefix",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.transactionFees = "_X1"
				return tx
			},
		},
		"malformed publicKey": {
			expErr: "transaction is altered and doesn't match the hash",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.publicKey = []byte{1}
				return tx
			},
		},
		"malformed from address": {
			expErr: "transaction is altered and doesn't match the hash",
			when: func() *Transaction {
				tx := validTransaction(t)
				tx.from = "0x12"
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

func TestEquals(t *testing.T) {
	tx := *validTransaction(t)
	assert.NotNil(t, tx)

	tx2 := *validTransaction(t)
	assert.NotNil(t, tx2)

	// nolint:gocritic
	ok, err := tx.Equals(&tx)
	assert.NoError(t, err)
	assert.True(t, ok)

	ok, _ = tx.Equals(&tx2)
	assert.False(t, ok)

	// invalid tx
	tx3 := Transaction{}
	ok, err = tx3.Equals(&tx2)
	assert.EqualError(t, err, "publicKey is empty")
	assert.False(t, ok)
}

func validTransaction(t *testing.T) *Transaction {
	keypair, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)

	pkyData, err := keypair.PublicKey.Raw()
	assert.NoError(t, err)

	mainChain, err := hexutil.Decode(ChainID)
	assert.NoError(t, err)

	addr, err := crypto.RawPublicToAddress(pkyData)
	assert.NoError(t, err)

	tx := Transaction{
		publicKey:       pkyData,
		nounce:          []byte{0},
		data:            []byte{1},
		from:            addr,
		to:              addr,
		chain:           mainChain,
		value:           "0x64",
		transactionFees: "0x64",
	}
	err = tx.Sign(keypair.PrivateKey)
	assert.NoError(t, err)
	return &tx
}
