//go:build !linux

package container

import "fmt"

func statInode(path string) (uint64, error) {
	return 0, fmt.Errorf("statInode not supported on this platform")
}
