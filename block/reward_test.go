package block

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetReward(t *testing.T) {
	reward, err := GetReward(0)
	assert.NoError(t, err)
	assert.Equal(t, "40000000000000000000", reward.String())

	reward, err = GetReward(3153600*2 - 1)
	assert.NoError(t, err)
	assert.Equal(t, "40000000000000000000", reward.String())

	reward, err = GetReward(3153600 * 2)
	assert.NoError(t, err)
	assert.Equal(t, "20000000000000000000", reward.String())

	reward, err = GetReward(3153600 * 6)
	assert.NoError(t, err)
	assert.Equal(t, "5000000000000000000", reward.String())
}
