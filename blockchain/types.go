package blockchain

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/filefilego/filefilego/common/hexutil"
	"google.golang.org/protobuf/proto"
)

// AddressState represents an address's state.
type AddressState struct {
	Balance []byte
	Nounce  []byte
}

// FileMetadata represents channel file metadata.
type FileMetadata struct {
	Name string
	Hash string
	Size uint64
	Path string
}

// GetBalance returns the balance as big int.
func (a *AddressState) GetBalance() (*big.Int, error) {
	if len(a.Balance) == 0 {
		return nil, errors.New("balance is empty")
	}
	return big.NewInt(0).SetBytes(a.Balance), nil
}

// SetBalance sets the balance to byte array.
func (a *AddressState) SetBalance(amount *big.Int) {
	zeroBig := big.NewInt(0)
	if zeroBig.Cmp(amount) == 0 {
		a.Balance = []byte{0}
	} else {
		a.Balance = amount.Bytes()
	}
}

// GetNounce returns the nounce as uint64.
func (a *AddressState) GetNounce() (uint64, error) {
	if len(a.Nounce) == 0 {
		return 0, errors.New("nounce is empty")
	}
	return hexutil.DecodeBigFromBytesToUint64(a.Nounce), nil
}

// SetNounce sets the balance to byte array.
func (a *AddressState) SetNounce(number uint64) {
	if number == 0 {
		a.Nounce = []byte{0}
	} else {
		a.Nounce = big.NewInt(0).SetUint64(number).Bytes()
	}
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
