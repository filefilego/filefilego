package block

import (
	"errors"
	"math/big"

	"github.com/filefilego/filefilego/common/currency"
)

// initia reward
const initialBlockReward = "40"

// estimation of total number of blocks per year
const totalNumberOfBlocksPerYear = 3153600

// GetReward returns the correct reward for a given block number.
func GetReward(blockNumber uint64) (*big.Int, error) {
	remaining := blockNumber / totalNumberOfBlocksPerYear
	reward, ok := big.NewInt(0).SetString(initialBlockReward, 10)
	if !ok {
		return nil, errors.New("failed to initialize int")
	}
	ffgCurrency := currency.FFG()
	ffgCurrency.Mul(ffgCurrency, reward)

	for i := uint64(0); i <= remaining; i++ {
		if i != 0 {
			if i%2 == 0 {
				ffgCurrency.Div(ffgCurrency, big.NewInt(2))
			}
		}
	}
	return ffgCurrency, nil
}
