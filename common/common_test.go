package common

import (
	"math/big"
	"testing"

	"github.com/filefilego/filefilego/node/protocols/messages"
	"github.com/stretchr/testify/assert"
)

func TestReverse(t *testing.T) {
	assert.Equal(t, "cba", Reverse("abc"))
	assert.Equal(t, "", Reverse(""))
}

func TestChunkString(t *testing.T) {
	chunks := ChunkString("abcde", 2)
	assert.Len(t, chunks, 3)
}

func TestFormatBigWithSeperator(t *testing.T) {
	assert.Equal(t, "10.00", FormatBigWithSeperator("1000", ".", 2))
}

func TestLeftPad2Len(t *testing.T) {
	assert.Equal(t, ",1000", LeftPad2Len("1000", ",", 5))
}

func TestIsValidPath(t *testing.T) {
	assert.Equal(t, false, IsValidPath("/home/x/../ffg.bin"))
	assert.Equal(t, true, IsValidPath("./home/./ffg.bin"))
}

func TestCalculateFileHosterTotalContractFees(t *testing.T) {
	contract := &messages.DownloadContractProto{
		FileHosterResponse: &messages.DataQueryResponseProto{
			FeesPerByte:     "0x1",
			FromPeerAddr:    "peerid",
			FileHashes:      [][]byte{{1}, {2}},
			FileHashesSizes: []uint64{10, 20},
			FileNames:       []string{"1.txt", "2.txt"},
			FileFeesPerByte: []string{"0x2", "0x4"},
		},
		FileHashesNeeded:      [][]byte{{1}, {2}},
		FileHashesNeededSizes: []uint64{10, 20},
		VerifierFees:          "0x1",
	}
	spGlobalFees := big.NewInt(1)
	calculated, err := CalculateFileHosterTotalContractFees(contract, spGlobalFees)
	assert.NoError(t, err)
	expected := big.NewInt(100)
	assert.Equal(t, expected.String(), calculated.String())

	// without file fees fallback to global
	contract = &messages.DownloadContractProto{
		FileHosterResponse: &messages.DataQueryResponseProto{
			FeesPerByte:     "0x1",
			FromPeerAddr:    "peerid",
			FileHashes:      [][]byte{{1}, {2}},
			FileHashesSizes: []uint64{10, 20},
			FileNames:       []string{"1.txt", "2.txt"},
			FileFeesPerByte: []string{"", ""},
		},
		FileHashesNeeded:      [][]byte{{1}, {2}},
		FileHashesNeededSizes: []uint64{10, 20},
		VerifierFees:          "0x1",
	}
	calculated, err = CalculateFileHosterTotalContractFees(contract, spGlobalFees)
	assert.NoError(t, err)
	expected = big.NewInt(30)
	assert.Equal(t, expected.String(), calculated.String())

	// invalid file fees
	contract = &messages.DownloadContractProto{
		FileHosterResponse: &messages.DataQueryResponseProto{
			FeesPerByte:     "0x1",
			FromPeerAddr:    "peerid",
			FileHashes:      [][]byte{{1}, {2}},
			FileHashesSizes: []uint64{10, 20},
			FileNames:       []string{"1.txt", "2.txt"},
			FileFeesPerByte: []string{"2", "s"},
		},
		FileHashesNeeded:      [][]byte{{1}, {2}},
		FileHashesNeededSizes: []uint64{10, 20},
		VerifierFees:          "0x1",
	}
	calculated, err = CalculateFileHosterTotalContractFees(contract, spGlobalFees)
	assert.Error(t, err)
	assert.Nil(t, calculated)
}
