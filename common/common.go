package common

import (
	// nolint:gosec

	"strings"
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
