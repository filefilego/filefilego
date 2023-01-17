package currency

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCurrency(t *testing.T) {
	assert.Equal(t, "0", FFGZero().String())
	assert.Equal(t, "1", FFGOne().String())
	assert.Equal(t, "1000", KFFG().String())
	assert.Equal(t, "1000000", MFFG().String())
	assert.Equal(t, "1000000000", GFFG().String())
	assert.Equal(t, "1000000000000", MicroFFG().String())
	assert.Equal(t, "1000000000000000", MiliFFG().String())
	assert.Equal(t, "1000000000000000000", FFG().String())
	assert.Equal(t, "1000000000000000000000", ZFFG().String())
}
