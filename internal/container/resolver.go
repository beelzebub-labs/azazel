package container

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Resolver maps cgroup IDs and PIDs to container IDs
type Resolver struct {
	mu    sync.RWMutex
	cache map[uint64]string // cgroup_id → container_id

	// Regex patterns for container ID extraction
	patterns []*regexp.Regexp
}

// NewResolver creates a new container resolver
func NewResolver() *Resolver {
	return &Resolver{
		cache: make(map[uint64]string),
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`/docker/([a-f0-9]{12,64})`),
			regexp.MustCompile(`docker-([a-f0-9]{12,64})\.scope`),
			regexp.MustCompile(`cri-containerd-([a-f0-9]{12,64})\.scope`),
			regexp.MustCompile(`libpod-([a-f0-9]{12,64})\.scope`),
			regexp.MustCompile(`crio-([a-f0-9]{12,64})\.scope`),
			regexp.MustCompile(`/kubepods/.+/([a-f0-9]{12,64})`),
		},
	}
}

// Resolve returns the container ID for a given cgroup ID and PID
func (r *Resolver) Resolve(cgroupID uint64, pid uint32) string {
	r.mu.RLock()
	if id, ok := r.cache[cgroupID]; ok {
		r.mu.RUnlock()
		return id
	}
	r.mu.RUnlock()

	containerID := r.resolveFromProc(pid)

	r.mu.Lock()
	r.cache[cgroupID] = containerID
	r.mu.Unlock()

	return containerID
}

// resolveFromProc reads /proc/<pid>/cgroup and extracts the container ID
func (r *Resolver) resolveFromProc(pid uint32) string {
	// Try host /proc first, then regular /proc
	paths := []string{
		fmt.Sprintf("/host/proc/%d/cgroup", pid),
		fmt.Sprintf("/proc/%d/cgroup", pid),
	}

	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			for _, pattern := range r.patterns {
				matches := pattern.FindStringSubmatch(line)
				if len(matches) >= 2 {
					f.Close()
					id := matches[1]
					if len(id) > 12 {
						id = id[:12]
					}
					return id
				}
			}
		}
		f.Close()
	}

	return ""
}

// GetCgroupIDForContainer walks /sys/fs/cgroup to find the cgroup directory
// matching the container ID and returns its inode number
func GetCgroupIDForContainer(containerID string) (uint64, error) {
	var cgroupID uint64
	found := false

	err := filepath.Walk("/sys/fs/cgroup", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if !info.IsDir() {
			return nil
		}
		if strings.Contains(info.Name(), containerID) {
			stat, err := statInode(path)
			if err != nil {
				return nil
			}
			cgroupID = stat
			found = true
			return filepath.SkipAll
		}
		return nil
	})

	if err != nil {
		return 0, fmt.Errorf("walk cgroup: %w", err)
	}
	if !found {
		return 0, fmt.Errorf("container %s not found in cgroup hierarchy", containerID)
	}

	return cgroupID, nil
}

// ListContainers scans /proc for running containers
func ListContainers() []ContainerInfo {
	var containers []ContainerInfo
	seen := make(map[string]bool)

	resolver := NewResolver()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		// Try /host/proc
		entries, err = os.ReadDir("/host/proc")
		if err != nil {
			log.Printf("[azazel] Warning: cannot read /proc: %v", err)
			return containers
		}
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Check if directory name is a number (PID)
		pid := uint32(0)
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}

		containerID := resolver.resolveFromProc(pid)
		if containerID == "" || seen[containerID] {
			continue
		}
		seen[containerID] = true

		containers = append(containers, ContainerInfo{
			ID:  containerID,
			PID: pid,
		})
	}

	return containers
}

// ContainerInfo holds basic container information
type ContainerInfo struct {
	ID  string
	PID uint32
}
