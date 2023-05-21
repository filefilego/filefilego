package common

import "golang.org/x/sys/windows"

// GetDirectoryFreeSpace returns the available space of a directory.
func GetDirectoryFreeSpace(directoryPath string) (uint64, error) {
	var free, total, avail uint64

	pathPtr, err := windows.UTF16PtrFromString(directoryPath)
	if err != nil {
		return err
	}

	err = windows.GetDiskFreeSpaceEx(pathPtr, &free, &total, &avail)
	if err != nil {
		return err
	}

	return free, nil
}
