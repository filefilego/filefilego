package validator

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewUncommitedBalance(t *testing.T) {
	balances := NewUncommitedBalance()
	assert.Empty(t, balances.addresses)
}

func TestUncommitedBalanceMethods(t *testing.T) {
	balances := NewUncommitedBalance()

	from := "0x01"
	assert.False(t, balances.IsInitialized(from))
	assert.False(t, balances.Subtract(from, big.NewInt(0), 0))

	balances.InitializeBalanceAndNounceFor(from, big.NewInt(10), 2)
	// initialize again should not update the initial values
	balances.InitializeBalanceAndNounceFor(from, big.NewInt(20), 10)
	assert.Equal(t, big.NewInt(10), balances.addresses[from].dbBalance)
	assert.Equal(t, uint64(2), balances.addresses[from].dbNounce)

	assert.True(t, balances.IsInitialized(from))

	// subtract a bigger amount should be false
	assert.False(t, balances.Subtract(from, big.NewInt(11), 0))

	// subtract smaller amound with a remainder
	assert.True(t, balances.Subtract(from, big.NewInt(9), 3))
	assert.Equal(t, big.NewInt(1), balances.addresses[from].dbBalance)
}
