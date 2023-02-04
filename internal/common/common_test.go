package common

import (
	"os"
	"path/filepath"
	"testing"

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
