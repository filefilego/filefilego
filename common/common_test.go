package common

import (
	"testing"

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
