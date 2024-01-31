package transaction

import (
	"fmt"
	sync "sync"
	"testing"

	ethTypes "github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
	"github.com/stretchr/testify/assert"
)

var (
	allTestsDone bool
	wg           sync.WaitGroup
)

func TestMain(m *testing.M) {
	wg.Add(7)

	go func() {
		wg.Wait()
		allTestsDone = true
		TestParseEthTX2(&testing.T{}) // Run the final test
	}()

	m.Run()
}

func TestNewTransaction(t *testing.T) {
	t.Parallel()
	t.Cleanup(func() {
		wg.Done()
	})

	cases := map[string]struct {
		tx     Transaction
		expErr string
	}{
		"invalid": {
			tx: Transaction{
				nounce: []byte{222},
				from:   "0x0123",
				to:     "0x0123",
				value:  "0x123",
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
			newTx := NewTransaction(tt.tx.Type(), tt.tx.PublicKey(), tt.tx.Nounce(), tt.tx.Data(), tt.tx.From(), tt.tx.To(), tt.tx.Value(), tt.tx.TransactionFees(), tt.tx.Chain())
			assert.NotNil(t, newTx)
		})
	}
}

func TestParseEthTX2(t *testing.T) {
	if !allTestsDone {
		t.Skip("Skipping final test until all others are complete because we will change the ChainIDGlobal and it will make the rest of tests fail")
	}

	ChainIDGlobal = 1
	raw := "02f872011c8405f5e10085027740ca5782520894b969b3f17071205ec1c928e7006111620fc0bfcf8712d7083f26a80080c001a07a14584e838032eaffe5b3f78b304d05e2ea3723f9099a6e06a1fa24bcfe448fa07886500164ad53a33baef4dd6b1a0e9dbd45465f7ef295afb2dcc4ba8724c8a6"
	tx, err := ParseEth(raw)
	assert.NoError(t, err)
	assert.NotNil(t, tx)

	txHashOriginal := "0x87d69a4734971ffee37c397274fe9909ef18ba17b2437d3bbc5b8b3be0b32ac8"

	fmt.Println("tx hash ", hexutil.Encode(tx.Hash()))

	hash, err := tx.CalculateHash()
	assert.NoError(t, err)
	assert.Equal(t, txHashOriginal, hexutil.Encode(hash))

	// another tx
	raw = "02f874018202688405f5e10085088ac5c910825208945c543c580288237bcb771d1677b8adab36d4138a8758d15e1762800080c080a02d6a0025789f6b7ca4cd700bc82fd9a8255d902d4aa8c6efa99ed20ef2dd65f0a048e1a0da1ffd32cac2ee67503ee1f2b86e450c1099d1518c0a6dc9e7f93ac4e0"
	tx, err = ParseEth(raw)
	assert.NoError(t, err)
	assert.NotNil(t, tx)

	txHashOriginal = "0x701b89261eff4a83a57503aa831f084954da25561084b1017db60018f869a04e"

	fmt.Println("tx hash ", hexutil.Encode(tx.Hash()))

	hash, err = tx.CalculateHash()
	assert.NoError(t, err)
	assert.Equal(t, txHashOriginal, hexutil.Encode(hash))
}

func TestParseEthTX(t *testing.T) {
	t.Cleanup(func() {
		wg.Done()
	})
	rawTX := "f866808203e882520894b000e8bbf1fa6b3391802393d8200b5936cf56f683989680808201a1a0a154e401962ae5135763bd348780a114b8564b83d46494d1d1ec6ff7cd1d6326a05c2662275ebc59ab44fd7c671c1e90ab99c090cc7d09a6b3d83e457b5dd9d88c"
	tx, err := ParseEth(rawTX)
	assert.NoError(t, err)
	assert.NotNil(t, tx)

	// check if the hash is correct
	var ethTx ethTypes.Transaction
	txData, err := hexutil.DecodeNoPrefix(rawTX)
	assert.NoError(t, err)

	hash := ethcrypto.Keccak256Hash(txData)
	fmt.Println("all tx hash ", hash.Hex())

	derivedTX, err := &ethTx, rlp.DecodeBytes(txData, &ethTx)
	assert.NoError(t, err)
	assert.EqualValues(t, derivedTX.Hash().Bytes(), tx.Hash())

	fmt.Println("original hash: ", derivedTX.Hash().Hex())

	// calculate hash from transaction data
	calculatedHash, err := tx.CalculateHash()
	assert.NoError(t, err)
	fmt.Println(hexutil.Encode(calculatedHash))

	assert.Equal(t, hexutil.Encode(calculatedHash), hash.Hex())

	v, r, s := derivedTX.RawSignatureValues()
	newTX := ethTypes.NewTx(&ethTypes.LegacyTx{
		Nonce:    derivedTX.Nonce(),
		GasPrice: derivedTX.GasPrice(),
		Gas:      derivedTX.Gas(),
		To:       derivedTX.To(),
		Value:    derivedTX.Value(),
		Data:     derivedTX.Data(),
		V:        v,
		R:        r,
		S:        s,
	})

	ms, _ := derivedTX.MarshalJSON()
	fmt.Println("derivedTX ", string(ms))

	// Serialize the transaction using RLP encoding
	rlpEncodedTx, err := rlp.EncodeToBytes(newTX)
	if err != nil {
		panic(err)
	}

	// Hash the RLP encoded transaction using Keccak-256
	txHash := ethcrypto.Keccak256(rlpEncodedTx)
	fmt.Println("Manual hash ", hexutil.Encode(txHash))
}

func TestCalculateHash(t *testing.T) {
	t.Parallel()
	t.Cleanup(func() {
		wg.Done()
	})

	cases := map[string]struct {
		tx     Transaction
		expErr string
	}{
		"invalid public key": {
			tx:     Transaction{},
			expErr: "publicKey is empty",
		},
		"invalid from": {
			tx: Transaction{
				publicKey: []byte{12},
				nounce:    []byte{222},
			},
			expErr: "from is empty",
		},
		"invalid nounce": {
			tx: Transaction{
				publicKey: []byte{12},
				from:      "0x0123",
			},
			expErr: "nounce is empty",
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
	t.Cleanup(func() {
		wg.Done()
	})
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
	t.Cleanup(func() {
		wg.Done()
	})

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
	t.Cleanup(func() {
		wg.Done()
	})
	tx := validTransaction(t)
	assert.NotNil(t, tx)
	ptx := ToProtoTransaction(*tx)
	assert.NotNil(t, ptx)
	derviedTx := ProtoTransactionToTransaction(ptx)
	assert.Equal(t, *tx, derviedTx)
}

func TestEquals(t *testing.T) {
	t.Cleanup(func() {
		wg.Done()
	})
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
