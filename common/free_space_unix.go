//go:build !windows
// +build !windows

package common

import "syscall"

// GetDirectoryFreeSpace returns the available space of a directory.
func GetDirectoryFreeSpace(directoryPath string) (uint64, error) {
	var freeSpace uint64
	var stat syscall.Statfs_t

	err := syscall.Statfs(directoryPath, &stat)
	if err == nil {
		freeSpace = stat.Bavail * uint64(stat.Bsize)
	}

	return freeSpace, err
}
