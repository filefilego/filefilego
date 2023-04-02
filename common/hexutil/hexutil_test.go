package hexutil

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeNoPrefix(t *testing.T) {
	str := EncodeNoPrefix([]byte{1})
	assert.Equal(t, "01", str)
}

func TestEncode(t *testing.T) {
	str := Encode([]byte{1})
	assert.Equal(t, "0x01", str)
}

func TestDecode(t *testing.T) {
	data, err := Decode("")
	assert.EqualError(t, err, "input is empty")
	assert.Empty(t, data)

	data, err = Decode("01")
	assert.EqualError(t, err, "hex prefix is missing")
	assert.Empty(t, data)

	data, err = Decode("0x01cddti")
	assert.EqualError(t, err, "failed to decode hex string: encoding/hex: invalid byte: U+0074 't'")
	assert.Empty(t, data)

	data, err = Decode("0x01")
	assert.NoError(t, err)
	assert.EqualValues(t, data, []byte{1})
}

func TestHas0xPrefix(t *testing.T) {
	assert.True(t, Has0xPrefix("0x01"))
}

func TestDecodeUint64(t *testing.T) {
	num, err := DecodeUint64("1")
	assert.EqualError(t, err, "hex string without 0x prefix")
	assert.Equal(t, uint64(0), num)

	num, err = DecodeUint64("0x1")
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), num)
}

func TestEncodeUint64(t *testing.T) {
	tmp := uint64(18446744073709551615)
	str := EncodeUint64(tmp)
	assert.Equal(t, "0xffffffffffffffff", str)

	tmp = uint64(1)
	str = EncodeUint64(tmp)
	assert.Equal(t, "0x1", str)
}

func TestEncodeInt64(t *testing.T) {
	tmp := int64(9223372036854775807)
	str := EncodeInt64(tmp)
	assert.Equal(t, "0x7fffffffffffffff", str)

	tmp = int64(17)
	str = EncodeInt64(tmp)
	assert.Equal(t, "0x11", str)

	tmp = int64(1)
	str = EncodeInt64(tmp)
	assert.Equal(t, "0x1", str)
}

func TestDecodeEncodeBig(t *testing.T) {
	_, err := DecodeBig("")
	assert.EqualError(t, err, "empty hex string")

	_, err = DecodeBig("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	assert.EqualError(t, err, "hex number > 256 bits")

	num, err := DecodeBig("0xffffffffffffffff")
	assert.NoError(t, err)
	assert.Equal(t, "18446744073709551615", num.String())

	str := EncodeBig(num)
	assert.Equal(t, "0xffffffffffffffff", str)

	num = num.SetInt64(0)
	str = EncodeBig(num)
	assert.Equal(t, "0x0", str)

	biggestUnit, ok := big.NewInt(0).SetString("1000000000000000000000", 10)
	assert.True(t, ok)
	assert.Equal(t, "1000000000000000000000", biggestUnit.String())
}

func TestDecodeBigFromBytesToUint64(t *testing.T) {
	num := DecodeBigFromBytesToUint64([]byte{1})
	assert.Equal(t, uint64(1), num)
}

func TestBigNumberConversion(t *testing.T) {
	timestampBig := big.NewInt(1)
	assert.Equal(t, []byte{0x1}, timestampBig.Bytes())

	bNum := big.NewInt(0).SetUint64(1)
	blockNumberBytes := bNum.Bytes()
	assert.Equal(t, []byte{0x1}, blockNumberBytes)

	// from bytes construct the
	bNum2 := bNum.SetBytes(timestampBig.Bytes())
	assert.Equal(t, int64(1), bNum2.Int64())

	// one byte
	assert.Len(t, bNum2.Bytes(), 1)
	assert.Len(t, bNum2.Text(16), 1)

	// one byte, 2 string bytes in hex
	bNum3 := bNum2.SetInt64(16)
	assert.Len(t, bNum3.Bytes(), 1)
	assert.Len(t, bNum3.Text(16), 2)
}

func TestXxx(t *testing.T) {
	bytesTwo := EncodeUint64ToBytes(2)
	hexRepresentation := EncodeUint64BytesToHexString(bytesTwo)
	assert.Equal(t, "0x2", hexRepresentation)
}

func TestExtractHex(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"This is a test string without hex values", ""},
		{"This is a test string with a valid hex value 0xABCDEF", "0xABCDEF"},
		{"This is a test string with an invalid hex value 0x12GHIJ", ""},
		{"This is a test string with multiple valid hex values 0x123456 and 0xABCDEF", "0x123456"},
		{"This is a test string with multiple invalid hex values 0x123 and 0xABC", ""},
	}

	for _, c := range cases {
		actual := ExtractHex(c.input)
		if actual != c.expected {
			t.Errorf("ExtractHex(%q) == %q, expected %q", c.input, actual, c.expected)
		}
	}
}
