package common

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"

	"github.com/filefilego/filefilego/common/hexutil"
)

// FileSize gets the file size
func FileSize(fullPath string) (int64, error) {
	fi, err := os.Stat(fullPath)
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// Sha1File performs a sha1 hash on a file
func Sha1File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hexutil.EncodeNoPrefix(h.Sum(nil)), nil
}

// Sha1String performs a sha1 hash on a string
func Sha256String(data string) (string, error) {
	h := sha256.New()
	io.WriteString(h, data)
	return hexutil.Encode(h.Sum(nil)), nil
}

// DirExists checks if destination dir exists
func DirExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// FileExists checks if destination file exists
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// Itob returns an 8-byte big endian representation of v.
func Itob(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

// I32tob convers unit32 to byte array
func I32tob(val uint32) []byte {
	r := make([]byte, 4)
	for i := uint32(0); i < 4; i++ {
		r[i] = byte((val >> (8 * i)) & 0xff)
	}
	return r
}

// Btoi32 converts bytearray to uint32
func Btoi32(val []byte) uint32 {
	r := uint32(0)
	for i := uint32(0); i < 4; i++ {
		r |= uint32(val[i]) << (8 * i)
	}
	return r
}
