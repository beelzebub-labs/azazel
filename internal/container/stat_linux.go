//go:build linux

package container

import (
	"fmt"
	"syscall"
)

// statInode returns the inode number for a path, used as cgroup ID
func statInode(path string) (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return stat.Ino, nil
}
