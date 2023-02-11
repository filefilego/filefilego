package common

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cbergoon/merkletree"
	"github.com/filefilego/filefilego/internal/common/hexutil"
	"github.com/filefilego/filefilego/internal/crypto"
	"github.com/stretchr/testify/assert"
)

func TestDirectoryFunctions(t *testing.T) {
	homeDir := HomeDir()
	assert.True(t, DirExists(homeDir))
	dirToBeCreated := "122839492384928349"
	t.Cleanup(func() {
		os.RemoveAll(filepath.Join(homeDir, dirToBeCreated))
	})

	assert.False(t, DirExists(filepath.Join(homeDir, dirToBeCreated)))
	err := CreateDirectory(filepath.Join(homeDir, dirToBeCreated))
	assert.NoError(t, err)
	assert.True(t, DirExists(filepath.Join(homeDir, dirToBeCreated)))
}

func TestFileFunctions(t *testing.T) {
	homeDir := HomeDir()
	assert.True(t, DirExists(homeDir))
	fileToBeCreated := "231283918239182931823.txt"
	t.Cleanup(func() {
		os.RemoveAll(filepath.Join(homeDir, fileToBeCreated))
	})

	assert.False(t, FileExists(filepath.Join(homeDir, fileToBeCreated)))
	filePath, err := WriteToFile([]byte("hello"), filepath.Join(homeDir, fileToBeCreated))
	assert.NoError(t, err)
	assert.True(t, FileExists(filePath))

	// FileSize
	size, err := FileSize(filePath)
	assert.NoError(t, err)
	assert.Equal(t, int64(5), size)
}

func TestHomeDir(t *testing.T) {
	homedir := HomeDir()
	assert.NotEmpty(t, homedir)
}

func TestDefaultDataDir(t *testing.T) {
	defaultDir := DefaultDataDir()
	assert.NotEmpty(t, defaultDir)
}

func TestFileSegmentsInfo(t *testing.T) {
	// file size is 11 bytes, with 5 segments and zero encyption
	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment := FileSegmentsInfo(11, 5, 0)
	assert.Equal(t, 4, howManySegments)
	assert.Equal(t, 3, segmentSizeBytes)
	assert.Equal(t, 0, totalSegmentsToEncrypt)
	assert.Equal(t, 0, encryptEverySegment)

	// file size is 12 bytes, with 6 segments and 4% enc
	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment = FileSegmentsInfo(12, 6, 4)
	assert.Equal(t, 6, howManySegments)
	assert.Equal(t, 2, segmentSizeBytes)
	assert.Equal(t, 1, totalSegmentsToEncrypt)
	assert.Equal(t, 6, encryptEverySegment)

	// file size is 12 bytes, with 6 segments and 100% enc
	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment = FileSegmentsInfo(12, 6, 100)
	assert.Equal(t, 6, howManySegments)
	assert.Equal(t, 2, segmentSizeBytes)
	assert.Equal(t, 6, totalSegmentsToEncrypt)
	assert.Equal(t, 1, encryptEverySegment)

	// file size is 12 bytes, with 6 segments and 50% enc
	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment = FileSegmentsInfo(12, 6, 50)
	assert.Equal(t, 6, howManySegments)
	assert.Equal(t, 2, segmentSizeBytes)
	assert.Equal(t, 3, totalSegmentsToEncrypt)
	assert.Equal(t, 2, encryptEverySegment)

	// file size is 12 bytes, with 6 segments and 50% enc
	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment = FileSegmentsInfo(57, 8, 60)
	assert.Equal(t, 8, howManySegments)
	assert.Equal(t, 8, segmentSizeBytes)
	assert.Equal(t, 5, totalSegmentsToEncrypt)
	assert.Equal(t, 1, encryptEverySegment)
}

func TestPrepareFileBlockRanges(t *testing.T) {
	// file size is 24 bytes, with 6 segments and 50% enc
	filesize := 24
	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment := FileSegmentsInfo(filesize, 6, 50)
	assert.Equal(t, 6, howManySegments)
	assert.Equal(t, 4, segmentSizeBytes)
	assert.Equal(t, 3, totalSegmentsToEncrypt)
	assert.Equal(t, 2, encryptEverySegment)
	randomSlice := []int{0, 1, 2, 3, 4, 5}
	assert.Len(t, randomSlice, 6)
	ranges, ok := PrepareFileBlockRanges(0, howManySegments-1, filesize, howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment, randomSlice)
	assert.True(t, ok)
	assert.Len(t, ranges, 6)
	totalEnc := 0

	for _, v := range ranges {
		if v.mustEncrypt {
			totalEnc++
		}
	}
	assert.Equal(t, totalSegmentsToEncrypt, totalEnc)

	// zero percent encryption
	filesize = 24
	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment = FileSegmentsInfo(filesize, 6, 0)
	assert.Equal(t, 6, howManySegments)
	assert.Equal(t, 4, segmentSizeBytes)
	assert.Equal(t, 0, totalSegmentsToEncrypt)
	assert.Equal(t, 0, encryptEverySegment)
	randomSlice = []int{0, 1, 2, 3, 4, 5}
	assert.Len(t, randomSlice, 6)
	ranges, ok = PrepareFileBlockRanges(0, howManySegments-1, filesize, howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment, randomSlice)
	assert.True(t, ok)
	assert.Len(t, ranges, 6)
	totalEnc = 0
	for _, v := range ranges {
		if v.mustEncrypt {
			totalEnc++
		}
	}
	assert.Equal(t, totalSegmentsToEncrypt, totalEnc)

	// 1 percent enc
	filesize = 24
	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment = FileSegmentsInfo(filesize, 6, 1)
	assert.Equal(t, 6, howManySegments)
	assert.Equal(t, 4, segmentSizeBytes)
	assert.Equal(t, 1, totalSegmentsToEncrypt)
	assert.Equal(t, 6, encryptEverySegment)
	randomSlice = []int{0, 1, 2, 3, 4, 5}
	assert.Len(t, randomSlice, 6)
	ranges, ok = PrepareFileBlockRanges(0, howManySegments-1, filesize, howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment, randomSlice)
	assert.True(t, ok)
	assert.Len(t, ranges, 6)
	totalEnc = 0
	for _, v := range ranges {
		if v.mustEncrypt {
			totalEnc++
		}
	}
	assert.Equal(t, totalSegmentsToEncrypt, totalEnc)
}

func TestGenerateRandomIntSlice(t *testing.T) {
	// this test makes sure we have all the elements in the slice
	// and run the function for 200 times
	for idx := 0; idx <= 200; idx++ {
		number := 120
		permutations := GenerateRandomIntSlice(number)
		assert.Len(t, permutations, number)
		for _, v := range permutations {
			found := false
			for j := 0; j < number; j++ {
				if v == j {
					found = true
				}
			}
			if !found {
				assert.Fail(t, "couldn't find number in permutation")
			}
		}

		// test how often a random slice is generated in a complete ascending order (0,1,2,3,..., n)
		total := 0
		for i, v := range permutations {
			if i == v {
				total++
			}
		}

		if total >= number-1 {
			assert.Fail(t, "all slice elements seems to be equal")
		}
	}
}

func TestHashFileBlockSegments(t *testing.T) {
	fileContent := "this is ffg network a decentralized data sharing network"
	outputFile := "testfile.txt"
	// 56 bytes
	assert.Len(t, fileContent, 56)
	_, err := WriteToFile([]byte(fileContent), outputFile)
	assert.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(outputFile)
	})

	howManySegments, _, _, _ := FileSegmentsInfo(56, 8, 0)
	orderedSlice := make([]int, howManySegments)
	for i := 0; i < howManySegments; i++ {
		orderedSlice[i] = i
	}

	merkleLeaves, err := HashFileBlockSegments(outputFile, howManySegments, orderedSlice)

	assert.NoError(t, err)
	assert.Len(t, merkleLeaves, howManySegments)

	merkleLeaves2, err := HashFileBlockSegments(outputFile, howManySegments, orderedSlice)
	assert.NoError(t, err)
	assert.Len(t, merkleLeaves2, howManySegments)
	assert.EqualValues(t, merkleLeaves, merkleLeaves2)
}

func TestGetFileMerkleRootHash(t *testing.T) {
	fileContent := "this is ffg network a decentralized data sharing network"
	outputFile := "testfilemerkle.txt"
	// 56 bytes
	assert.Len(t, fileContent, 56)
	_, err := WriteToFile([]byte(fileContent), outputFile)
	assert.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(outputFile)
	})

	howManySegments, _, _, _ := FileSegmentsInfo(56, 8, 0)
	orderedSlice := make([]int, howManySegments)
	for i := 0; i < howManySegments; i++ {
		orderedSlice[i] = i
	}

	merkleRootHash, err := GetFileMerkleRootHash(outputFile, howManySegments, orderedSlice)
	assert.NoError(t, err)
	assert.Len(t, merkleRootHash, 32)

	merkleRootHash2, err := GetFileMerkleRootHash(outputFile, howManySegments, orderedSlice)
	assert.NoError(t, err)
	assert.Len(t, merkleRootHash2, 32)
	assert.EqualValues(t, merkleRootHash, merkleRootHash2)
}

func TestEncryptDecryption(t *testing.T) {
	fileContent := "this is ffg network a decentralized data sharing network+"
	inputFile := "sampletext.txt"
	outputFile := "sampletext.enc.txt"
	outputFileDecryptedRestored := "sampletext.original.txt"
	percentageDecrypt := 10
	totalSegments := 8

	_, err := WriteToFile([]byte(fileContent), inputFile)
	assert.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(inputFile)
		os.RemoveAll(outputFile)
		os.RemoveAll(outputFileDecryptedRestored)
	})

	input, err := os.Open(inputFile)
	assert.NoError(t, err)
	inputStats, err := input.Stat()
	assert.NoError(t, err)

	howManySegmentsForInputFile, _, _, _ := FileSegmentsInfo(int(inputStats.Size()), totalSegments, 0)
	orderedSlice := make([]int, howManySegmentsForInputFile)
	for i := 0; i < howManySegmentsForInputFile; i++ {
		orderedSlice[i] = i
	}
	merkleTree, err := HashFileBlockSegments(inputFile, howManySegmentsForInputFile, orderedSlice)
	assert.NoError(t, err)
	assert.Len(t, merkleTree, totalSegments)

	// nolint:gofumpt
	output, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, 0777)
	assert.NoError(t, err)

	outputOriginalRestored, err := os.OpenFile(outputFileDecryptedRestored, os.O_RDWR|os.O_CREATE, 0777)
	assert.NoError(t, err)

	start := time.Now()
	// key, err := crypto.RandomEntropy(32)
	// assert.NoError(t, err)
	// iv, err := crypto.RandomEntropy(24)
	// assert.NoError(t, err)
	// encryptor, err := NewEncryptor(EncryptionTypeChacha20, key, iv)
	// assert.NoError(t, err)
	key, err := crypto.RandomEntropy(32)
	assert.NoError(t, err)
	iv, err := crypto.RandomEntropy(16)
	assert.NoError(t, err)
	encryptor, err := NewEncryptor(EncryptionTypeAES256, key, iv)
	assert.NoError(t, err)
	elapsed := time.Since(start)
	log.Printf("RandomEntropy for key and iv took %s", elapsed)

	randomSlices := GenerateRandomIntSlice(howManySegmentsForInputFile)
	start = time.Now()
	err = EncryptWriteOutput(int(inputStats.Size()), totalSegments, percentageDecrypt, randomSlices, input, output, encryptor)
	elapsed = time.Since(start)
	log.Printf("EncryptWriteOutput took %s", elapsed)
	assert.NoError(t, err)

	err = output.Sync()
	assert.NoError(t, err)

	err = output.Close()
	assert.NoError(t, err)

	// get the merkle tree of the output file
	// merkleTreeEncryptedFile, err := HashFileBlockSegments(outputFile, totalSegments)
	// assert.NoError(t, err)
	// assert.Len(t, merkleTreeEncryptedFile, totalSegments)

	// reopen output file
	// nolint:gofumpt
	output, err = os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, 0777)
	assert.NoError(t, err)

	outputStats, err := output.Stat()
	assert.NoError(t, err)

	start = time.Now()
	err = DecryptFileSegments(int(outputStats.Size()), totalSegments, percentageDecrypt, randomSlices, output, outputOriginalRestored, encryptor)
	elapsed = time.Since(start)
	log.Printf("DecryptFileSegments took %s", elapsed)
	assert.NoError(t, err)

	hashOfOriginalFile, err := crypto.Sha1File(inputFile)
	assert.NoError(t, err)
	hashOfDecryptedRestoredFile, err := crypto.Sha1File(outputFileDecryptedRestored)
	assert.NoError(t, err)
	assert.Equal(t, hashOfDecryptedRestoredFile, hashOfOriginalFile)
}

// this function tests the randomization of the file segments to test
// if the merkle hash is properlly derived from a randomized slice
func TestMerkleHashAfterSegmentRandomizationNoEncryption(t *testing.T) {
	fileContent := "this is ffg network a decentralized data sharing network+"
	inputFile := "merkle.txt"
	outputFile := "merkle.enc.txt"
	outputFileDecryptedRestored := "merkle.original.txt"
	percentageEcrypt := 0
	totalSegments := 8

	_, err := WriteToFile([]byte(fileContent), inputFile)
	assert.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(inputFile)
		os.RemoveAll(outputFile)
		os.RemoveAll(outputFileDecryptedRestored)
	})

	input, err := os.Open(inputFile)
	assert.NoError(t, err)
	inputStats, err := input.Stat()
	assert.NoError(t, err)

	howManySegmentsForInputFile, _, _, encryptEverySegment := FileSegmentsInfo(int(inputStats.Size()), totalSegments, 0)
	assert.Equal(t, howManySegmentsForInputFile, totalSegments)

	orderedSlice := make([]int, howManySegmentsForInputFile)
	for i := 0; i < howManySegmentsForInputFile; i++ {
		orderedSlice[i] = i
	}

	inputMerkleRootHash, err := GetFileMerkleRootHash(inputFile, totalSegments, orderedSlice)
	assert.NoError(t, err)

	merkleTree, err := HashFileBlockSegments(inputFile, totalSegments, orderedSlice)
	assert.NoError(t, err)
	assert.Len(t, merkleTree, totalSegments)

	// nolint:gofumpt
	output, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, 0777)
	assert.NoError(t, err)

	outputOriginalRestored, err := os.OpenFile(outputFileDecryptedRestored, os.O_RDWR|os.O_CREATE, 0777)
	assert.NoError(t, err)

	start := time.Now()
	key, err := crypto.RandomEntropy(32)
	assert.NoError(t, err)
	iv, err := crypto.RandomEntropy(16)
	assert.NoError(t, err)
	encryptor, err := NewEncryptor(EncryptionTypeAES256, key, iv)
	assert.NoError(t, err)
	elapsed := time.Since(start)
	log.Printf("RandomEntropy for key and iv took %s", elapsed)

	randomSlices := GenerateRandomIntSlice(howManySegmentsForInputFile)
	start = time.Now()
	err = EncryptWriteOutput(int(inputStats.Size()), totalSegments, percentageEcrypt, randomSlices, input, output, encryptor)
	elapsed = time.Since(start)
	log.Printf("EncryptWriteOutput took %s", elapsed)
	assert.NoError(t, err)

	err = output.Sync()
	assert.NoError(t, err)

	err = output.Close()
	assert.NoError(t, err)

	// get the encrypted merkle hash to see if it matches the original value given the random slice
	merkleTreeRandomizedSegments, err := HashFileBlockSegments(outputFile, totalSegments, orderedSlice)
	assert.NoError(t, err)
	assert.Len(t, merkleTreeRandomizedSegments, howManySegmentsForInputFile)

	reorderedMerkle, err := RetrieveMerkleTreeNodesFromFileWithRawData(encryptEverySegment, randomSlices, merkleTreeRandomizedSegments, []merkletree.Content{})
	assert.NoError(t, err)
	assert.EqualValues(t, merkleTree, reorderedMerkle)

	merkleOfReorderedMerkle, err := GetFileMerkleRootHashFromNodes(reorderedMerkle)
	assert.NoError(t, err)

	// check if the merkle root hashes are equal
	assert.Equal(t, inputMerkleRootHash, merkleOfReorderedMerkle)
	assert.Equal(t, "0x4c06842c3aa270970f6b0d5ade8a155b268f33e35c19849f1bbd24374bcc8f8a", hexutil.Encode(merkleOfReorderedMerkle))

	// reopen output file
	// nolint:gofumpt
	output, err = os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, 0777)
	assert.NoError(t, err)

	outputStats, err := output.Stat()
	assert.NoError(t, err)

	start = time.Now()
	err = DecryptFileSegments(int(outputStats.Size()), totalSegments, percentageEcrypt, randomSlices, output, outputOriginalRestored, encryptor)
	elapsed = time.Since(start)
	log.Printf("DecryptFileSegments took %s", elapsed)
	assert.NoError(t, err)

	hashOfOriginalFile, err := crypto.Sha1File(inputFile)
	assert.NoError(t, err)
	hashOfDecryptedRestoredFile, err := crypto.Sha1File(outputFileDecryptedRestored)
	assert.NoError(t, err)
	assert.Equal(t, hashOfDecryptedRestoredFile, hashOfOriginalFile)
}

func TestEncryptAndVerifyMerkle(t *testing.T) {
	fileContent := "this is ffg network a decentralized data sharing network+"
	inputFile := "encryptverify.txt"
	outputFile := "encryptverify.enc.txt"
	outputFileDecryptedRestored := "encryptverify.original.txt"
	outputUnencryptedSegments := "encryptverify.unencrypted.txt"
	percentageEcrypt := 60
	totalSegments := 8

	//
	_, err := WriteToFile([]byte(fileContent), inputFile)
	assert.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(inputFile)
		os.RemoveAll(outputFile)
		os.RemoveAll(outputFileDecryptedRestored)
		os.RemoveAll(outputUnencryptedSegments)
	})

	input, err := os.Open(inputFile)
	assert.NoError(t, err)
	inputStats, err := input.Stat()
	assert.NoError(t, err)

	howManySegmentsForInputFile, _, totalSegmentsToEncrypt, encryptEverySegment := FileSegmentsInfo(int(inputStats.Size()), totalSegments, percentageEcrypt)

	log.Println("howManySegmentsForInputFile ", howManySegmentsForInputFile)
	log.Println("totalSegmentsToEncrypt ", totalSegmentsToEncrypt)
	log.Println("encryptEverySegment ", encryptEverySegment)

	orderedSlice := make([]int, howManySegmentsForInputFile)
	for i := 0; i < howManySegmentsForInputFile; i++ {
		orderedSlice[i] = i
	}

	inputMerkleRootHash, err := GetFileMerkleRootHash(inputFile, totalSegments, orderedSlice)
	assert.NoError(t, err)

	merkleTree, err := HashFileBlockSegments(inputFile, totalSegments, orderedSlice)
	assert.NoError(t, err)
	assert.Len(t, merkleTree, totalSegments)

	// nolint:gofumpt
	output, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, 0777)
	assert.NoError(t, err)

	outputOriginalRestored, err := os.OpenFile(outputFileDecryptedRestored, os.O_RDWR|os.O_CREATE, 0777)
	assert.NoError(t, err)

	key, err := crypto.RandomEntropy(32)
	assert.NoError(t, err)
	iv, err := crypto.RandomEntropy(16)
	assert.NoError(t, err)
	encryptor, err := NewEncryptor(EncryptionTypeAES256, key, iv)
	assert.NoError(t, err)

	randomSlices := GenerateRandomIntSlice(howManySegmentsForInputFile)
	fmt.Println("randomSlices ", randomSlices)

	outputUnencrypted, err := os.OpenFile(outputUnencryptedSegments, os.O_RDWR|os.O_CREATE, 0777)
	assert.NoError(t, err)

	fmt.Printf("WriteUnencryptedSegments totalSegments: %d  percentageEcrypt: %d\n", totalSegments, percentageEcrypt)
	err = WriteUnencryptedSegments(int(inputStats.Size()), totalSegments, percentageEcrypt, randomSlices, input, outputUnencrypted)
	assert.NoError(t, err)
	outputUnencrypted.Seek(0, 0)

	// reset input
	input.Seek(0, 0)

	err = EncryptWriteOutput(int(inputStats.Size()), totalSegments, percentageEcrypt, randomSlices, input, output, encryptor)
	assert.NoError(t, err)

	err = output.Sync()
	assert.NoError(t, err)

	err = output.Close()
	assert.NoError(t, err)

	// get the encrypted merkle hash to see if it matches the original value given the random slice
	merkleTreeRandomizedSegments, err := HashFileBlockSegments(outputFile, totalSegments, orderedSlice)
	assert.NoError(t, err)
	assert.Len(t, merkleTreeRandomizedSegments, howManySegmentsForInputFile)

	// assert.NotEqual(t, 0, totalSegmentsToEncrypt)
	// assert.Equal(t, 8, encryptEverySegment)

	orderedSliceForRawfile := []int{}
	for i := 0; i < totalSegmentsToEncrypt; i++ {
		orderedSliceForRawfile = append(orderedSliceForRawfile, i)
	}

	log.Println("original input merkleTree")
	for _, v := range merkleTree {
		vhash, _ := v.CalculateHash()
		log.Println(hexutil.Encode(vhash))
	}

	log.Println("==================")

	fmt.Println("geting merkle of the bytes sent to verifier totalSegmentsToEncrypt:", totalSegmentsToEncrypt)
	merkleOfRawSegmentsBeforeEncryption, err := HashFileBlockSegments(outputUnencryptedSegments, totalSegmentsToEncrypt, orderedSliceForRawfile)
	assert.NoError(t, err)
	assert.Len(t, merkleOfRawSegmentsBeforeEncryption, totalSegmentsToEncrypt)

	reorderedMerkle, err := RetrieveMerkleTreeNodesFromFileWithRawData(encryptEverySegment, randomSlices, merkleTreeRandomizedSegments, merkleOfRawSegmentsBeforeEncryption)

	log.Println("reorderedMerkle")
	for _, v := range reorderedMerkle {
		vhash, _ := v.CalculateHash()
		log.Println(hexutil.Encode(vhash))
	}

	assert.NoError(t, err)
	assert.EqualValues(t, merkleTree, reorderedMerkle)

	merkleOfReorderedMerkle, err := GetFileMerkleRootHashFromNodes(reorderedMerkle)
	assert.NoError(t, err)

	// check if the merkle root hashes are equal
	assert.Equal(t, inputMerkleRootHash, merkleOfReorderedMerkle)
	assert.Equal(t, "0x4c06842c3aa270970f6b0d5ade8a155b268f33e35c19849f1bbd24374bcc8f8a", hexutil.Encode(merkleOfReorderedMerkle))

	// reopen output file
	// nolint:gofumpt
	output, err = os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, 0777)
	assert.NoError(t, err)

	outputStats, err := output.Stat()
	assert.NoError(t, err)

	err = DecryptFileSegments(int(outputStats.Size()), totalSegments, percentageEcrypt, randomSlices, output, outputOriginalRestored, encryptor)
	assert.NoError(t, err)

	hashOfOriginalFile, err := crypto.Sha1File(inputFile)
	assert.NoError(t, err)
	hashOfDecryptedRestoredFile, err := crypto.Sha1File(outputFileDecryptedRestored)
	assert.NoError(t, err)
	assert.Equal(t, hashOfDecryptedRestoredFile, hashOfOriginalFile)
}
