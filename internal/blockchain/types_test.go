package blockchain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddressStateFunctions(t *testing.T) {
	addrState := AddressState{
		Balance: []byte{22},
		Nounce:  []byte{4},
	}

	// to proto message
	protoAddr := ToAddressStateProto(addrState)
	assert.NotNil(t, protoAddr)

	// back to addressState
	derived := AddressStateProtoToAddressState(protoAddr)
	assert.Equal(t, addrState, derived)
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
