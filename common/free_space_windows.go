package common

import "golang.org/x/sys/windows"

// GetDirectoryFreeSpace returns the available space of a directory.
func GetDirectoryFreeSpace(directoryPath string) (uint64, error) {
	var freeSpace uint64
	var err error

	var free, total, avail uint64

	pathPtr, err := windows.UTF16PtrFromString(directoryPath)
	if err != nil {
		panic(err)
	}
	err = windows.GetDiskFreeSpaceEx(pathPtr, &free, &total, &avail)

	if err == nil {
		freeSpace = free
	}

	return freeSpace, err
}
