package common

import (
	// nolint:gosec

	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// DirExists checks if destination dir exists
func DirExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// CreateDirectory creates a directory.
func CreateDirectory(path string) error {
	src, err := os.Stat(path)
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(path, os.ModePerm)
		if errDir != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
		return nil
	}

	if src.Mode().IsRegular() {
		return errors.New("path is a file")
	}

	return nil
}

// FileExists checks if destination file exists
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// WriteToFile writes data to a file.
func WriteToFile(data []byte, filePath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
		return "", fmt.Errorf("failed to open path: %w", err)
	}
	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to create path: %w", err)
	}
	defer file.Close()
	_, err = file.Write(data)
	if err != nil {
		return "", fmt.Errorf("failed to write data to path: %w", err)
	}
	return filePath, nil
}

// FileSize gets the file size
func FileSize(fullPath string) (int64, error) {
	fi, err := os.Stat(fullPath)
	if err != nil {
		return 0, fmt.Errorf("failed to get file stat: %w", err)
	}
	return fi.Size(), nil
}

// DefaultDataDir returns the default datadir.
func DefaultDataDir() string {
	home := HomeDir()
	if home != "" {
		switch runtime.GOOS {
		case "darwin":
			return filepath.Join(home, "Library", "filefilego_data")
		case "windows":
			return filepath.Join(home, "AppData", "Roaming", "filefilego_data")
		default:
			return filepath.Join(home, ".filefilego_data")
		}
	}
	return ""
}

// HomeDir returns the home directory.
func HomeDir() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if usr, err := user.Current(); err == nil {
		return usr.HomeDir
	}
	return ""
}

// Reverse
func Reverse(s string) string {
	n := len(s)
	runes := make([]rune, n)
	for _, rune := range s {
		n--
		runes[n] = rune
	}
	return string(runes[n:])
}

// ChunkString
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

// FormatBigWithSeperator
func FormatBigWithSeperator(s string, sep string, index int) string {
	s = Reverse(s)
	prts := ChunkString(s, index)
	return Reverse(prts[0] + "." + prts[1])
}

// LeftPad2Len
func LeftPad2Len(s string, padStr string, overallLen int) string {
	if len(s) > overallLen {
		return s
	}
	padCountInt := 1 + ((overallLen - len(padStr)) / len(padStr))
	retStr := strings.Repeat(padStr, padCountInt) + s
	return retStr[(len(retStr) - overallLen):]
}
