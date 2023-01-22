package block

import (
	"testing"

	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/stretchr/testify/assert"
)

func TestGetGenesisBlock(t *testing.T) {
	// valid
	genesisblockValid, err := GetGenesisBlock()
	assert.NoError(t, err)
	assert.NotNil(t, genesisblockValid)
	data := hexutil.Encode(genesisblockValid.Hash)
	assert.Equal(t, []byte{0}, genesisblockValid.Transactions[0].Nounce)
	assert.Equal(t, uint64(0), genesisblockValid.Number)
	assert.Equal(t, "0xe381741db5e128d572c459b41151dff44c713b6fa72d6107b69e630fe8ddebf9", data)
	assert.Equal(t, "0xdd9a374e8dce9d656073ec153580301b7d2c3850", genesisblockValid.Transactions[0].From)
}
