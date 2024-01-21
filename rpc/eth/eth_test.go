package eth

import (
	"math/big"
	"testing"

	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/stretchr/testify/assert"
)

func TestXxx(t *testing.T) {

	s := hexutil.EncodeBig(big.NewInt(1000000000000000))

	assert.Equal(t, "", s)
}
