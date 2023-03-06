package block

import (
	"errors"
	"math/big"

	"github.com/filefilego/filefilego/common/currency"
)

const initialBlockReward = "40"

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

// CalculateReward prints the estimated supply emission.
// func CalculateReward() {
// 	// 500 Million
// 	totalCoins := float64(500 * 1000000)
// 	blocksPerYear := float64(3153600)
// 	reward := float64(40)
// 	totalCoinMined := float64(0)
// 	for i := 0; i <= 100; i++ {
// 		if i != 0 {
// 			if i%2 == 0 {
// 				reward /= 2
// 			}
// 		}
// 		totalCoinMined += blocksPerYear * reward
// 		totalCoins -= (blocksPerYear * reward)
// 		fmt.Printf("total coins left in year: %d with reward: %f : %f === total coin mined: %f\n", i+1, reward, totalCoins, totalCoinMined)
// 	}
// 	fmt.Println("total coins left: ", totalCoins)
// }
