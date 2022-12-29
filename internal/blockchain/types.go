package blockchain

import (
	"fmt"

	"google.golang.org/protobuf/proto"
)

// AddressState represents an address's state.
type AddressState struct {
	Balance []byte
	Nounce  []byte
}

// ToAddressStateProto returns the proto representation of a state.
func ToAddressStateProto(state AddressState) *AddressStateProto {
	addrStateProto := &AddressStateProto{
		Balance: make([]byte, len(state.Balance)),
		Nounce:  make([]byte, len(state.Nounce)),
	}

	copy(addrStateProto.Balance, state.Balance)
	copy(addrStateProto.Nounce, state.Nounce)

	return addrStateProto
}

// AddressStateProtoToAddressState returns the AddressState from a AddressStateProto.
func AddressStateProtoToAddressState(state *AddressStateProto) AddressState {
	addrState := AddressState{
		Balance: make([]byte, len(state.Balance)),
		Nounce:  make([]byte, len(state.Nounce)),
	}

	copy(addrState.Balance, state.Balance)
	copy(addrState.Nounce, state.Nounce)

	return addrState
}

// MarshalAddressStateProto serializes an address state to a protobuf message.
func MarshalAddressStateProto(b *AddressStateProto) ([]byte, error) {
	addrData, err := proto.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal address state: %w", err)
	}
	return addrData, nil
}

// UnmarshalProtoBlock unserializes a byte array to a protobuf address state.
func UnmarshalAddressStateProto(data []byte) (*AddressStateProto, error) {
	addr := AddressStateProto{}
	if err := proto.Unmarshal(data, &addr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal an address state: %w", err)
	}
	return &addr, nil
}
