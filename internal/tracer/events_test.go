package tracer

import (
	"testing"
)

func TestEventTypeName(t *testing.T) {
	tests := []struct {
		eventType uint32
		want      string
	}{
		{EventProcessExec, "process_exec"},
		{EventProcessExit, "process_exit"},
		{EventFileOpen, "file_open"},
		{EventFileWrite, "file_write"},
		{EventFileRead, "file_read"},
		{EventFileUnlink, "file_unlink"},
		{EventNetConnect, "net_connect"},
		{EventNetAccept, "net_accept"},
		{EventNetBind, "net_bind"},
		{EventNetSendto, "net_sendto"},
		{EventNetRecvfrom, "net_recvfrom"},
		{EventNetDNS, "net_dns"},
		{EventSyscallGeneric, "syscall_generic"},
		{EventProcessClone, "process_clone"},
		{EventFileRename, "file_rename"},
		{EventNetListen, "net_listen"},
		{EventMmapExec, "mmap_exec"},
		{EventPtrace, "ptrace"},
		{EventModuleLoad, "module_load"},
		{9999, "unknown_9999"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := EventTypeName(tt.eventType)
			if got != tt.want {
				t.Errorf("EventTypeName(%d) = %v, want %v", tt.eventType, got, tt.want)
			}
		})
	}
}

func TestEventTypeConstants(t *testing.T) {
	// Verify constants are unique
	seen := make(map[uint32]bool)
	eventTypes := []uint32{
		EventProcessExec,
		EventProcessExit,
		EventFileOpen,
		EventFileWrite,
		EventFileRead,
		EventFileUnlink,
		EventNetConnect,
		EventNetAccept,
		EventNetBind,
		EventNetSendto,
		EventNetRecvfrom,
		EventNetDNS,
		EventSyscallGeneric,
		EventProcessClone,
		EventFileRename,
		EventNetListen,
		EventMmapExec,
		EventPtrace,
		EventModuleLoad,
	}

	for _, et := range eventTypes {
		if seen[et] {
			t.Errorf("Duplicate event type constant: %d", et)
		}
		seen[et] = true
	}

	// Verify they are sequential starting from 1
	for i, et := range eventTypes {
		expected := uint32(i + 1)
		if et != expected {
			t.Errorf("Event type %d is not sequential, expected %d", et, expected)
		}
	}
}

func TestParsedEventStructure(t *testing.T) {
	// Test that ParsedEvent can be created and has expected fields
	ev := &ParsedEvent{
		Timestamp:   "2025-01-15T14:30:22.123456789Z",
		EventType:   "process_exec",
		PID:         12345,
		TGID:        12345,
		PPID:        12300,
		UID:         1000,
		GID:         1000,
		Comm:        "bash",
		CgroupID:    6789,
		ContainerID: "abc123def456",
		Filename:    "/bin/bash",
	}

	if ev.EventType != "process_exec" {
		t.Errorf("EventType = %v, want process_exec", ev.EventType)
	}
	if ev.PID != 12345 {
		t.Errorf("PID = %v, want 12345", ev.PID)
	}
	if ev.Filename != "/bin/bash" {
		t.Errorf("Filename = %v, want /bin/bash", ev.Filename)
	}
}

func TestMaxConstants(t *testing.T) {
	// Verify max constants are reasonable
	if MaxFilenameLen <= 0 {
		t.Error("MaxFilenameLen should be positive")
	}
	if MaxArgsLen <= 0 {
		t.Error("MaxArgsLen should be positive")
	}
	if MaxCommLen <= 0 {
		t.Error("MaxCommLen should be positive")
	}

	// Verify they match expected values
	if MaxFilenameLen != 256 {
		t.Errorf("MaxFilenameLen = %d, expected 256", MaxFilenameLen)
	}
	if MaxArgsLen != 256 {
		t.Errorf("MaxArgsLen = %d, expected 256", MaxArgsLen)
	}
	if MaxCommLen != 16 {
		t.Errorf("MaxCommLen = %d, expected 16", MaxCommLen)
	}
}

func TestNetworkAddressFormatting(t *testing.T) {
	// Test IPv4 address formatting
	ev := &ParsedEvent{
		EventType: "net_connect",
		DstAddr:   "192.168.1.1",
		DstPort:   443,
	}

	if ev.DstAddr != "192.168.1.1" {
		t.Errorf("DstAddr = %v, want 192.168.1.1", ev.DstAddr)
	}
	if ev.DstPort != 443 {
		t.Errorf("DstPort = %v, want 443", ev.DstPort)
	}
}

func TestNetworkEventFields(t *testing.T) {
	// Verify network event specific fields
	ev := &ParsedEvent{
		EventType: "net_connect",
		SaFamily:  "AF_INET",
		DstAddr:   "1.1.1.1",
		DstPort:   80,
	}

	if ev.SaFamily != "AF_INET" {
		t.Errorf("SaFamily = %v, want AF_INET", ev.SaFamily)
	}
	if ev.DstAddr != "1.1.1.1" {
		t.Errorf("DstAddr = %v, want 1.1.1.1", ev.DstAddr)
	}
	if ev.DstPort != 80 {
		t.Errorf("DstPort = %v, want 80", ev.DstPort)
	}
}

func TestFileEventFields(t *testing.T) {
	// Verify file event specific fields
	flags := int32(0x0001) // O_RDONLY
	ev := &ParsedEvent{
		EventType: "file_open",
		Filename:  "/etc/passwd",
		Flags:     &flags,
	}

	if ev.Filename != "/etc/passwd" {
		t.Errorf("Filename = %v, want /etc/passwd", ev.Filename)
	}
	if ev.Flags == nil {
		t.Fatal("Flags should not be nil")
	}
	if *ev.Flags != 0x0001 {
		t.Errorf("Flags = %v, want 0x0001", *ev.Flags)
	}
}

func TestProcessEventFields(t *testing.T) {
	// Verify process event specific fields
	exitCode := int32(0)
	ev := &ParsedEvent{
		EventType: "process_exit",
		PID:       12345,
		ExitCode:  &exitCode,
	}

	if ev.ExitCode == nil {
		t.Fatal("ExitCode should not be nil")
	}
	if *ev.ExitCode != 0 {
		t.Errorf("ExitCode = %v, want 0", *ev.ExitCode)
	}
}

func TestMmapEventFields(t *testing.T) {
	// Verify mmap event specific fields
	addr := uint64(0x7f0000000000)
	length := uint64(4096)
	prot := uint32(0x7)  // PROT_READ|PROT_WRITE|PROT_EXEC
	flags := uint32(0x2) // MAP_PRIVATE

	ev := &ParsedEvent{
		EventType: "mmap_exec",
		Addr:      &addr,
		Len:       &length,
		Prot:      &prot,
		MmapFlags: &flags,
	}

	if ev.Addr == nil || *ev.Addr != addr {
		t.Errorf("Addr = %v, want %v", ev.Addr, addr)
	}
	if ev.Len == nil || *ev.Len != length {
		t.Errorf("Len = %v, want %v", ev.Len, length)
	}
	if ev.Prot == nil || *ev.Prot != prot {
		t.Errorf("Prot = %v, want %v", ev.Prot, prot)
	}
	if ev.MmapFlags == nil || *ev.MmapFlags != flags {
		t.Errorf("MmapFlags = %v, want %v", ev.MmapFlags, flags)
	}
}

// Helper function for pointer creation
func pointer[T any](v T) *T {
	return &v
}
