package block

import (
	"os"
	"testing"

	"github.com/filefilego/filefilego/internal/common"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/stretchr/testify/assert"
)

func TestGetGenesisBlock(t *testing.T) {
	// valid
	genesisblockValid, err := GetGenesisBlock("genesis.protoblock")
	assert.NoError(t, err)
	assert.NotNil(t, genesisblockValid)
	data := hexutil.Encode(genesisblockValid.Hash)
	assert.Equal(t, "0xe381741db5e128d572c459b41151dff44c713b6fa72d6107b69e630fe8ddebf9", data)

	// file doesnt exist
	genesisblock, err := GetGenesisBlock("genesis.protoblock_notavailable")
	assert.EqualError(t, err, "failed to read genesis block file: open genesis.protoblock_notavailable: no such file or directory")
	assert.Nil(t, genesisblock)

	// create an invalid genesis file
	path, err := common.WriteToFile([]byte{34}, "genesis.protoblock.invalid")
	assert.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll("genesis.protoblock.invalid")
	})
	genesisblock, err = GetGenesisBlock(path)
	assert.ErrorContains(t, err, "failed to unmarshal genesis block file: failed to unmarshal a block:")
	assert.Nil(t, genesisblock)

	// fail validation by removing hash of block
	pblock := ToProtoBlock(*genesisblockValid)
	pblock.Hash = []byte{}
	invalidProtoBlock, err := MarshalProtoBlock(pblock)
	assert.NoError(t, err)
	path, err = common.WriteToFile(invalidProtoBlock, "genesis.protoblock.invalid")
	assert.NoError(t, err)
	genesisblock, err = GetGenesisBlock(path)
	assert.EqualError(t, err, "failed to validate genesis block: hash is empty")
	assert.Nil(t, genesisblock)
}
