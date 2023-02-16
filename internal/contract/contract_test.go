package contract

import (
	"os"
	"testing"

	"github.com/filefilego/filefilego/internal/common"
	"github.com/filefilego/filefilego/internal/database"
	"github.com/filefilego/filefilego/internal/node/protocols/messages"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestNew(t *testing.T) {
	store, err := New(nil)
	assert.EqualError(t, err, "database is nil")
	assert.Nil(t, store)

	store, err = New(&database.DB{})
	assert.NoError(t, err)
	assert.NotNil(t, store)
}

func TestStoreMethods(t *testing.T) {
	db, err := leveldb.OpenFile("store.db", nil)
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("store.db")
	})

	driver, err := database.New(db)
	assert.NoError(t, err)

	store, err := New(driver)
	assert.NoError(t, err)

	_, err = store.GetContractFileInfo("123", []byte{})
	assert.EqualError(t, err, "contract not found")

	contract, err := store.GetContract("0x11")
	assert.EqualError(t, err, "contract 0x11 not found")
	assert.Nil(t, contract)

	err = store.CreateContract(&messages.DownloadContractProto{ContractHash: []byte{10}})
	assert.NoError(t, err)
	// create with same contract hash
	err = store.CreateContract(&messages.DownloadContractProto{ContractHash: []byte{10}})
	assert.EqualError(t, err, "contract already exists with 0x0a hash")

	contract, err = store.GetContract("0x0a")
	assert.NoError(t, err)
	assert.NotNil(t, contract)

	fileHash := []byte{33}
	err = store.SetMerkleTreeNodes("0x0a", fileHash, [][]byte{{14}})
	assert.NoError(t, err)

	err = store.SetMerkleTreeNodes("0x0a", fileHash, [][]byte{{14}})
	assert.NoError(t, err)

	fileInfo, err := store.GetContractFileInfo("0x0a", fileHash)
	assert.NoError(t, err)
	assert.Len(t, fileInfo.MerkleTreeNodes, 1)

	key := []byte{2}
	iv := []byte{3}
	randomizedSegments := []int{2, 1, 0}

	err = store.SetKeyIVEncryptionTypeRandomizedFileSegments("0x0a", fileHash, key, iv, common.EncryptionTypeAES256, randomizedSegments)
	assert.NoError(t, err)

	fileInfo, err = store.GetContractFileInfo("0x0a", fileHash)
	assert.NoError(t, err)
	assert.Len(t, fileInfo.MerkleTreeNodes, 1)
	assert.Equal(t, fileInfo.Key, key)
	assert.Equal(t, fileInfo.IV, iv)
	assert.Equal(t, randomizedSegments, fileInfo.RandomSegments)
	assert.Equal(t, fileInfo.EncryptionType, common.EncryptionTypeAES256)

	err = store.SetProofOfTransferVerified("0x0a", fileHash, true)
	assert.NoError(t, err)
	err = store.SetReceivedUnencryptedDataFromFileHoster("0x0a", fileHash, true)
	assert.NoError(t, err)

	fileInfo, err = store.GetContractFileInfo("0x0a", fileHash)
	assert.NoError(t, err)
	assert.Equal(t, true, fileInfo.ProofOfTransferVerified)
	assert.Equal(t, true, fileInfo.ReceivedUnencryptedDataFromFileHoster)

	// save to db
	err = store.persistToDB()
	assert.NoError(t, err)

	// create a new db and see if we can read the data there
	store2, err := New(driver)
	assert.NoError(t, err)
	_ = store2.LoadFromDB()

	fileInfo, err = store2.GetContractFileInfo("0x0a", fileHash)
	assert.NoError(t, err)
	assert.Len(t, store2.contracts, 1)
	assert.Equal(t, true, fileInfo.ProofOfTransferVerified)
	assert.Equal(t, true, fileInfo.ReceivedUnencryptedDataFromFileHoster)
	assert.Len(t, fileInfo.MerkleTreeNodes, 1)
	assert.Equal(t, fileInfo.Key, key)
	assert.Equal(t, fileInfo.IV, iv)
	assert.Equal(t, randomizedSegments, fileInfo.RandomSegments)
	assert.Equal(t, fileInfo.EncryptionType, common.EncryptionTypeAES256)
	assert.EqualValues(t, [][]byte{{14}}, fileInfo.MerkleTreeNodes)

	contract, err = store2.GetContract("0x0a")
	assert.NoError(t, err)
	assert.NotNil(t, contract)
	assert.EqualValues(t, []byte{10}, contract.ContractHash)

	err = store2.DeleteContract("0x0a")
	assert.NoError(t, err)

	contract, err = store2.GetContract("0x0a")
	assert.EqualError(t, err, "contract 0x0a not found")
	assert.Nil(t, contract)

	fileInfo, err = store2.GetContractFileInfo("0x0a", fileHash)
	assert.EqualError(t, err, "contract not found")
}
