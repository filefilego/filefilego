package common

import (
	// nolint:gosec

	"bytes"
	"fmt"
	"math/big"
	"strings"

	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/node/protocols/messages"
)

const (
	// FFGNetPubSubBlocksTXQuery is a pub sub topic name to receive transactions, data queries and blocks.
	FFGNetPubSubBlocksTXQuery = "ffgnet_pubsub"

	// FFGNetPubSubStorageQuery is a pub sub topic name to receive storage queryies.
	FFGNetPubSubStorageQuery = "ffgnet_pubsub_storage"
)

// Reverse a string.
func Reverse(s string) string {
	n := len(s)
	runes := make([]rune, n)
	for _, rune := range s {
		n--
		runes[n] = rune
	}
	return string(runes[n:])
}

// ChunkString chunks a string based on the chunk size.
func ChunkString(s string, chunkSize int) []string {
	var chunks []string
	runes := []rune(s)

	if len(runes) == 0 {
		return []string{s}
	}

	for i := 0; i < len(runes); i += chunkSize {
		nn := i + chunkSize
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
	}
	return chunks
}

// FormatBigWithSeperator formats a big number with separator.
func FormatBigWithSeperator(s string, sep string, index int) string {
	s = Reverse(s)
	prts := ChunkString(s, index)
	return Reverse(prts[0] + sep + prts[1])
}

// LeftPad2Len add padding deparator.
func LeftPad2Len(s string, padStr string, overallLen int) string {
	if len(s) > overallLen {
		return s
	}
	padCountInt := 1 + ((overallLen - len(padStr)) / len(padStr))
	retStr := strings.Repeat(padStr, padCountInt) + s
	return retStr[(len(retStr) - overallLen):]
}

// IsValidPath checks if path contains more than one "." character.
func IsValidPath(s string) bool {
	return !strings.Contains(s, "..")
}

// CalculateFileHosterTotalContractFees given a download contract calculates the
// amount required by the file hoster
func CalculateFileHosterTotalContractFees(downloadContract *messages.DownloadContractProto, fileHosterFeesPerByte *big.Int) (*big.Int, error) {
	totalFileHosterFees := big.NewInt(0)
	for _, v := range downloadContract.FileHashesNeeded {
		for i, x := range downloadContract.FileHosterResponse.FileHashes {
			if bytes.Equal(v, x) {
				fileSize := downloadContract.FileHosterResponse.FileHashesSizes[i]
				fileFees := downloadContract.FileHosterResponse.FileFeesPerByte[i]
				f := big.NewInt(0)
				if fileFees == "" {
					f = f.Mul(fileHosterFeesPerByte, big.NewInt(0).SetUint64(fileSize))
				} else {
					decodedFee, err := hexutil.DecodeBig(fileFees)
					if err != nil {
						return nil, fmt.Errorf("failed to decode file fees: %w", err)
					}
					f = f.Mul(decodedFee, big.NewInt(0).SetUint64(fileSize))
				}

				// add to the total
				totalFileHosterFees = totalFileHosterFees.Add(totalFileHosterFees, f)
			}
		}
	}
	return totalFileHosterFees, nil
}

// Contains checks is an element is within a list.
func Contains(elements []string, el string) bool {
	for _, s := range elements {
		s = strings.TrimSpace(s)
		if s == el || s == "*" {
			return true
		}
	}
	return false
}

// ChainID represents the main-net chain id.
const ChainID = "0x01"
