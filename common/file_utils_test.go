package common

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/filefilego/filefilego/crypto"
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
	assert.Equal(t, 4, totalSegmentsToEncrypt)
	assert.Equal(t, 2, encryptEverySegment)
}

func TestPrepareFileBlockRanges(t *testing.T) {
	filesize := 57
	percentageEcrypt := 21
	totalSegmentsDesired := 16

	howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment := FileSegmentsInfo(filesize, totalSegmentsDesired, percentageEcrypt)
	assert.Equal(t, 15, howManySegments)
	assert.Equal(t, 4, segmentSizeBytes)
	assert.Equal(t, 3, totalSegmentsToEncrypt)
	assert.Equal(t, 4, encryptEverySegment)
	randomSlice := []int{10, 7, 0, 6, 5, 1, 2, 8, 12, 13, 9, 4, 3, 11, 14}
	assert.Len(t, randomSlice, 15)
	ranges, ok := PrepareFileBlockRanges(0, howManySegments-1, filesize, howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment, randomSlice)
	assert.True(t, ok)
	assert.Len(t, ranges, 15)
	totalEnc := 0
	orders := []int{}
	for i, v := range ranges {
		if v.mustEncrypt {
			fmt.Println("must be encrypted ", i)
			totalEnc++
			orders = append(orders, i)
		}
	}

	assert.EqualValues(t, []int{2, 7, 11}, orders)
	assert.Equal(t, totalSegmentsToEncrypt, totalEnc)

	ranges, ok = PrepareFileBlockRanges(0, 9, filesize, howManySegments, segmentSizeBytes, totalSegmentsToEncrypt, encryptEverySegment, randomSlice)
	assert.True(t, ok)
	assert.Len(t, ranges, 10)
	totalEnc = 0
	orders = []int{}
	for i, v := range ranges {
		if v.mustEncrypt {
			fmt.Println("must be encrypted ", i)
			totalEnc++
			orders = append(orders, i)
		}
	}

	assert.EqualValues(t, []int{2, 7}, orders)
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
	// nolint:goconst
	fileContent := "this is ffg network a decentralized data sharing network+"
	inputFile := "sampletext.txt"
	outputFinalFile := "sampletext.enc.txt"
	outputFilePart1 := "sampletext.enc.1.txt"
	outputFileDecryptedRestored := "sampletext.original.txt"

	percentageDecrypt := 100
	totalSegments := 8

	_, err := WriteToFile([]byte(fileContent), inputFile)
	assert.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(inputFile)
		os.RemoveAll(outputFinalFile)
		os.RemoveAll(outputFilePart1)
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

	outputOriginalRestored, err := os.OpenFile(outputFileDecryptedRestored, os.O_RDWR|os.O_CREATE, os.ModePerm)
	assert.NoError(t, err)
	assert.NotNil(t, outputOriginalRestored)

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
	output1, err := os.OpenFile(outputFilePart1, os.O_RDWR|os.O_CREATE, os.ModePerm)
	assert.NoError(t, err)

	err = EncryptWriteOutput(int(inputStats.Size()), 0, 2, totalSegments, percentageDecrypt, randomSlices, input, output1, encryptor)
	assert.NoError(t, err)

	_, err = input.Seek(0, 0)
	assert.NoError(t, err)

	err = EncryptWriteOutput(int(inputStats.Size()), 3, 5, totalSegments, percentageDecrypt, randomSlices, input, output1, encryptor)
	assert.NoError(t, err)

	_, err = input.Seek(0, 0)
	assert.NoError(t, err)

	err = EncryptWriteOutput(int(inputStats.Size()), 6, 13, totalSegments, percentageDecrypt, randomSlices, input, output1, encryptor)
	assert.NoError(t, err)

	_, err = input.Seek(0, 0)
	assert.NoError(t, err)

	err = EncryptWriteOutput(int(inputStats.Size()), 14, 20, totalSegments, percentageDecrypt, randomSlices, input, output1, encryptor)
	assert.NoError(t, err)

	_, err = input.Seek(0, 0)
	assert.NoError(t, err)

	err = EncryptWriteOutput(int(inputStats.Size()), 21, 22, totalSegments, percentageDecrypt, randomSlices, input, output1, encryptor)
	assert.NoError(t, err)

	_, err = input.Seek(0, 0)
	assert.NoError(t, err)

	err = EncryptWriteOutput(int(inputStats.Size()), 23, 24, totalSegments, percentageDecrypt, randomSlices, input, output1, encryptor)
	assert.NoError(t, err)

	_, err = input.Seek(0, 0)
	assert.NoError(t, err)

	err = EncryptWriteOutput(int(inputStats.Size()), 25, 25, totalSegments, percentageDecrypt, randomSlices, input, output1, encryptor)
	assert.NoError(t, err)

	_, err = input.Seek(0, 0)
	assert.NoError(t, err)

	err = EncryptWriteOutput(int(inputStats.Size()), 26, 40, totalSegments, percentageDecrypt, randomSlices, input, output1, encryptor)
	assert.NoError(t, err)

	_, err = input.Seek(0, 0)
	assert.NoError(t, err)

	err = EncryptWriteOutput(int(inputStats.Size()), 41, int(inputStats.Size()-1), totalSegments, percentageDecrypt, randomSlices, input, output1, encryptor)
	assert.NoError(t, err)

	_, err = input.Seek(0, 0)
	assert.NoError(t, err)

	err = output1.Close()
	assert.NoError(t, err)

	err = ConcatenateFiles(outputFinalFile, []string{outputFilePart1})
	assert.NoError(t, err)

	// reopen output file
	output, err := os.OpenFile(outputFinalFile, os.O_RDWR|os.O_CREATE, os.ModePerm)
	assert.NoError(t, err)

	outputStats, err := output.Stat()
	assert.NoError(t, err)
	start = time.Now()
	err = DecryptFileSegments(int(outputStats.Size()), totalSegments, percentageDecrypt, randomSlices, output, outputOriginalRestored, encryptor, false)
	assert.NoError(t, err)
	elapsed = time.Since(start)
	log.Printf("DecryptFileSegments took %s", elapsed)

	hashOfOriginalFile, err := crypto.Sha1File(inputFile)
	assert.NoError(t, err)
	hashOfDecryptedRestoredFile, err := crypto.Sha1File(outputFileDecryptedRestored)
	assert.NoError(t, err)
	assert.Equal(t, hashOfDecryptedRestoredFile, hashOfOriginalFile)
}

func TestTestEncryptAndVerifyMerkle(t *testing.T) {
	fileContent := "this is ffg network a decentralized data sharing network+"
	inputFile := "encryptverify.txt"
	outputFile := "encryptverify.enc.txt"
	outputFileDecryptedRestored := "encryptverify.original.txt"
	outputUnencryptedSegments := "encryptverify.unencrypted.txt"

	percentageEcrypt := 37
	totalSegmentsDesired := 4096

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
	input.Close()

	// get the possible file segment size given the filesize and desired segment size.
	howManySegmentsAllowedForFile, _, totalSegmentsToEncrypt, encryptEverySegment := FileSegmentsInfo(int(inputStats.Size()), totalSegmentsDesired, percentageEcrypt)

	// ordered slice to get the merkle tree nodes of a file in order
	orderedSlice := make([]int, howManySegmentsAllowedForFile)
	for i := 0; i < howManySegmentsAllowedForFile; i++ {
		orderedSlice[i] = i
	}
	// merkle root
	inputMerkleRootHash, err := GetFileMerkleRootHash(inputFile, howManySegmentsAllowedForFile, orderedSlice)
	assert.NoError(t, err)

	// merkle tree of input with all the nodes
	merkleTree, err := HashFileBlockSegments(inputFile, howManySegmentsAllowedForFile, orderedSlice)
	assert.NoError(t, err)
	assert.Len(t, merkleTree, howManySegmentsAllowedForFile)

	output, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, os.ModePerm)
	assert.NoError(t, err)

	key, err := crypto.RandomEntropy(32)
	assert.NoError(t, err)
	iv, err := crypto.RandomEntropy(16)
	assert.NoError(t, err)
	encryptor, err := NewEncryptor(EncryptionTypeAES256, key, iv)
	assert.NoError(t, err)

	// generate a random slice so we shuffle the segments order to be sent
	randomSlices := GenerateRandomIntSlice(howManySegmentsAllowedForFile)
	outputUnencrypted, err := os.OpenFile(outputUnencryptedSegments, os.O_RDWR|os.O_CREATE, os.ModePerm)
	assert.NoError(t, err)

	input, err = os.Open(inputFile)
	assert.NoError(t, err)

	// this step is to read the segments bytes which are indicated to be encrypted
	// they are needed by verifier
	err = WriteUnencryptedSegments(int(inputStats.Size()), howManySegmentsAllowedForFile, percentageEcrypt, randomSlices, input, outputUnencrypted)
	assert.NoError(t, err)
	outputUnencrypted.Close()
	input.Close()

	orderedSliceForRawfile := []int{}
	for i := 0; i < totalSegmentsToEncrypt; i++ {
		orderedSliceForRawfile = append(orderedSliceForRawfile, i)
	}
	// encrypt the raw segments
	// needed by verifier
	outputUnencrypted, err = os.Open(outputUnencryptedSegments)
	assert.NoError(t, err)
	outputUnencryptedStats, err := outputUnencrypted.Stat()
	assert.NoError(t, err)
	merkleHashedEncryptedRaw, err := EncryptAndHashSegments(int(outputUnencryptedStats.Size()), totalSegmentsToEncrypt, orderedSliceForRawfile, outputUnencrypted, encryptor)
	assert.NoError(t, err)
	outputUnencrypted.Close()
	assert.Len(t, merkleHashedEncryptedRaw, totalSegmentsToEncrypt)

	// encrypt and shuffle segments based on the random slice
	input, err = os.Open(inputFile)
	assert.NoError(t, err)
	err = EncryptWriteOutput(int(inputStats.Size()), 0, int(inputStats.Size()), howManySegmentsAllowedForFile, percentageEcrypt, randomSlices, input, output, encryptor)
	assert.NoError(t, err)

	input.Close()

	err = output.Close()
	assert.NoError(t, err)

	// get the encrypted file's merkle hash to see if it matches the original value given the random slice
	merkleTreeRandomizedSegments, err := HashFileBlockSegments(outputFile, howManySegmentsAllowedForFile, orderedSlice)
	assert.NoError(t, err)
	assert.Len(t, merkleTreeRandomizedSegments, howManySegmentsAllowedForFile)
	merkleTreeRootHashRandomizedSegments, err := GetFileMerkleRootHashFromNodes(merkleTreeRandomizedSegments)
	assert.NoError(t, err)

	// merge the merkle hash nodes of the raw segments with the merkle hashes of the whole file sent to the node (encrypted and shuffled)
	// the result should be exactly the same merkle hashes of the merkleTreeRandomizedSegments
	merkleTreeRandomizedSegmentsMergedWithRawSegmentsHash, err := RetrieveMerkleTreeNodesFromFileWithRawData(encryptEverySegment, randomSlices, merkleTreeRandomizedSegments, merkleHashedEncryptedRaw)
	assert.NoError(t, err)
	assert.EqualValues(t, merkleTreeRandomizedSegments, merkleTreeRandomizedSegmentsMergedWithRawSegmentsHash)
	merkleRootHashOfEncryptedSegmentsMergedWithEncryptedFile, err := GetFileMerkleRootHashFromNodes(merkleTreeRandomizedSegmentsMergedWithRawSegmentsHash)
	assert.NoError(t, err)
	assert.EqualValues(t, merkleTreeRootHashRandomizedSegments, merkleRootHashOfEncryptedSegmentsMergedWithEncryptedFile)

	// get the merkle tree nodes of the WriteUnencryptedSegments result
	merkleOfRawSegmentsBeforeEncryption, err := HashFileBlockSegments(outputUnencryptedSegments, totalSegmentsToEncrypt, orderedSliceForRawfile)
	if totalSegmentsToEncrypt > 0 {
		assert.NoError(t, err)
		assert.Len(t, merkleOfRawSegmentsBeforeEncryption, totalSegmentsToEncrypt)
	}

	// given the merkle hashes from the encrypted file and the ones derived from the raw file we can get the final merkle tree
	reorderedMerkle, err := RetrieveMerkleTreeNodesFromFileWithRawData(encryptEverySegment, randomSlices, merkleTreeRandomizedSegments, merkleOfRawSegmentsBeforeEncryption)
	assert.NoError(t, err)
	assert.EqualValues(t, merkleTree, reorderedMerkle)

	// get the merkle root hash of the derived file
	merkleOfReorderedMerkle, err := GetFileMerkleRootHashFromNodes(reorderedMerkle)
	assert.NoError(t, err)

	// check if the merkle root hashes are equal
	assert.Equal(t, inputMerkleRootHash, merkleOfReorderedMerkle)

	// reopen output file
	output, err = os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, os.ModePerm)
	assert.NoError(t, err)

	outputStats, err := output.Stat()
	assert.NoError(t, err)

	outputOriginalRestored, err := os.OpenFile(outputFileDecryptedRestored, os.O_RDWR|os.O_CREATE, os.ModePerm)
	assert.NoError(t, err)

	// decrypt the file segments
	err = DecryptFileSegments(int(outputStats.Size()), howManySegmentsAllowedForFile, percentageEcrypt, randomSlices, output, outputOriginalRestored, encryptor, false)
	assert.NoError(t, err)
	outputOriginalRestored.Close()

	// hash the original input with the final output to see if they match
	hashOfOriginalFile, err := crypto.Sha1File(inputFile)
	assert.NoError(t, err)
	hashOfDecryptedRestoredFile, err := crypto.Sha1File(outputFileDecryptedRestored)
	assert.NoError(t, err)
	assert.Equal(t, hashOfDecryptedRestoredFile, hashOfOriginalFile)
	output.Close()
}

func TestConcatenateFiles(t *testing.T) {
	inputFiles := []string{"file1.txt", "file2.txt", "file3.txt"}
	for _, inputFile := range inputFiles {
		f, err := os.Create(inputFile)
		if err != nil {
			t.Fatalf("failed to create temporary input file %s: %v", inputFile, err)
		}
		defer f.Close()

		if _, err := f.WriteString("Hello, world!\n"); err != nil {
			t.Fatalf("failed to write to temporary input file %s: %v", inputFile, err)
		}
	}

	outputFile := "output.txt"

	t.Cleanup(func() {
		os.RemoveAll(outputFile)
		os.RemoveAll("file1.txt")
		os.RemoveAll("file2.txt")
		os.RemoveAll("file3.txt")
	})

	if err := ConcatenateFiles(outputFile, inputFiles); err != nil {
		t.Fatalf("failed to concatenate files: %v", err)
	}

	// read the contents of the output file and ensure it matches the input files
	expectedContents := "Hello, world!\nHello, world!\nHello, world!\n"
	actualContents, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if string(actualContents) != expectedContents {
		t.Fatalf("output file contents do not match expected contents:\nexpected: %q\nactual: %q", expectedContents, actualContents)
	}

	// rest with an empty list of input files
	emptyInputFiles := []string{}
	if err := ConcatenateFiles(outputFile, emptyInputFiles); err != nil {
		t.Fatalf("failed to concatenate files with empty input files list: %v", err)
	}

	// rest with a non-existent input file
	nonexistentInputFiles := []string{"nonexistent.txt"}
	if err := ConcatenateFiles(outputFile, nonexistentInputFiles); err == nil {
		t.Fatalf("expected error when concatenating non-existent input file, but no error was returned")
	}

	// rest with a non-existent output file directory
	nonexistentOutputFile := "nonexistent/output.txt"
	if err := ConcatenateFiles(nonexistentOutputFile, inputFiles); err == nil {
		t.Fatalf("expected error when creating output file in non-existent directory, but no error was returned")
	}
}

func TestGetBytesRangesToEncryptAndSend(t *testing.T) {
	fileBlockRanges := []FileBlockRange{
		{
			mustEncrypt: true,
			from:        0,
			to:          3,
		},
		{
			mustEncrypt: false,
			from:        4,
			to:          7,
		},
		{
			mustEncrypt: true,
			from:        8,
			to:          11,
		},
		{
			mustEncrypt: false,
			from:        12,
			to:          15,
		},
		{
			mustEncrypt: false,
			from:        16,
			to:          18,
		},
	}

	ranges := getBytesRangesToEncryptAndSend(6, 10, 4, fileBlockRanges)
	assert.Len(t, ranges, 2)
	assert.Equal(t, false, ranges[0].encrypt)
	assert.Equal(t, 4, ranges[0].fromPartStart)
	assert.Equal(t, 7, ranges[0].toPartEnd)
	assert.Equal(t, 6, ranges[0].fromSendData)
	assert.Equal(t, 7, ranges[0].to)

	assert.Equal(t, true, ranges[1].encrypt)
	assert.Equal(t, 8, ranges[1].fromPartStart)
	assert.Equal(t, 11, ranges[1].toPartEnd)
	assert.Equal(t, 8, ranges[1].fromSendData)
	assert.Equal(t, 10, ranges[1].to)
}
