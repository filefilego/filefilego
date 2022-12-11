package common

import (
	// nolint:gosec
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	"github.com/filefilego/filefilego/internal/common/hexutil"
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

// Sha1File performs a sha1 hash on a file
func Sha1File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// nolint:gosec
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to copy file content to sha1 handler: %w", err)
	}

	return hexutil.EncodeNoPrefix(h.Sum(nil)), nil
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
