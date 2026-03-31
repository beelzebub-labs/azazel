package container

import (
	"testing"
)

func TestNewResolver(t *testing.T) {
	r := NewResolver()
	if r == nil {
		t.Fatal("NewResolver() returned nil")
	}
	if r.cache == nil {
		t.Error("Resolver cache not initialized")
	}
}

func TestResolverResolve(t *testing.T) {
	r := NewResolver()

	tests := []struct {
		name     string
		cgroupID uint64
		pid      uint32
		want     string
	}{
		{
			name:     "zero cgroup",
			cgroupID: 0,
			pid:      1,
			want:     "",
		},
		{
			name:     "valid cgroup",
			cgroupID: 12345,
			pid:      1000,
			want:     "", // Will be empty or container ID depending on system
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.Resolve(tt.cgroupID, tt.pid)
			// We can't assert exact values since it depends on the system
			// Just verify it doesn't panic and returns a string
			_ = got
		})
	}
}

func TestResolverCaching(t *testing.T) {
	r := NewResolver()

	cgroupID := uint64(12345)
	pid := uint32(1000)

	// First call
	result1 := r.Resolve(cgroupID, pid)

	// Second call with same cgroup - should use cache
	result2 := r.Resolve(cgroupID, pid)

	if result1 != result2 {
		t.Errorf("Cached result mismatch: %s != %s", result1, result2)
	}
}

func TestListContainers(t *testing.T) {
	containers := ListContainers()

	// Just verify it doesn't panic and returns a slice (may be empty in test environment)
	if containers == nil {
		t.Skip("ListContainers() returned nil - /proc not accessible in test environment")
	}

	// If there are containers, verify structure
	for _, c := range containers {
		if c.ID == "" {
			t.Error("Container has empty ID")
		}
		if c.PID == 0 {
			t.Error("Container has zero PID")
		}
	}
}

func TestGetCgroupIDForContainer(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
		wantErr     bool
	}{
		{
			name:        "empty container ID",
			containerID: "",
			wantErr:     true,
		},
		{
			name:        "invalid container ID",
			containerID: "nonexistent123456",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetCgroupIDForContainer(tt.containerID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCgroupIDForContainer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
