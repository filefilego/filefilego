package blockchain

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddressStateFunctions(t *testing.T) {
	addrState := AddressState{
		Balance: []byte{3},
		Nounce:  []byte{4},
	}

	// to proto message
	protoAddr := ToAddressStateProto(addrState)
	assert.NotNil(t, protoAddr)

	// back to addressState
	derived := AddressStateProtoToAddressState(protoAddr)
	assert.Equal(t, addrState, derived)

	// get balance
	balance, err := addrState.GetBalance()
	assert.NoError(t, err)
	assert.EqualValues(t, addrState.Balance, balance.Bytes())

	// reset balance
	addrState.Balance = []byte{}
	balance, err = addrState.GetBalance()
	assert.EqualError(t, err, "balance is empty")
	assert.Nil(t, balance)

	// get nounce
	nounce, err := addrState.GetNounce()
	assert.NoError(t, err)
	assert.Equal(t, uint64(4), nounce)

	// reset nounce
	addrState.Nounce = []byte{}
	nounce, err = addrState.GetNounce()
	assert.EqualError(t, err, "nounce is empty")
	assert.Equal(t, uint64(0), nounce)

	tmpState := AddressState{}
	tmpState.SetBalance(big.NewInt(12))
	tmpState.SetNounce(11)
	assert.Equal(t, AddressState{Balance: []byte{12}, Nounce: []byte{11}}, tmpState)

	// set balance with zero
	tmpState = AddressState{}
	tmpState.SetBalance(big.NewInt(0))
	assert.NotEmpty(t, tmpState.Balance)
}

func TestMarshalUnmarshalAddressStateProto(t *testing.T) {
	addrState := AddressState{
		Balance: []byte{22},
		Nounce:  []byte{4},
	}

	// to proto message
	protoAddr := ToAddressStateProto(addrState)
	assert.NotNil(t, protoAddr)

	// marshal valid
	data, err := MarshalAddressStateProto(protoAddr)
	assert.NoError(t, err)
	assert.NotNil(t, data)

	// unmarshal an invalid message
	derivedProto, err := UnmarshalAddressStateProto([]byte{23})
	assert.Error(t, err)
	assert.Nil(t, derivedProto)

	// unmarshal a valid message
	derivedProto, err = UnmarshalAddressStateProto(data)
	assert.NoError(t, err)
	assert.NotNil(t, derivedProto)

	assert.EqualValues(t, protoAddr.Balance, derivedProto.Balance)
	assert.EqualValues(t, protoAddr.Nounce, derivedProto.Nounce)
}
