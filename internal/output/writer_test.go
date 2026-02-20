package output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/azazel/internal/tracer"
)

func TestNewWriter(t *testing.T) {
	tests := []struct {
		name       string
		outputPath string
		stdout     bool
		pretty     bool
		wantErr    bool
	}{
		{
			name:       "stdout only",
			outputPath: "",
			stdout:     true,
			pretty:     false,
			wantErr:    false,
		},
		{
			name:       "file output",
			outputPath: filepath.Join(t.TempDir(), "test.json"),
			stdout:     false,
			pretty:     false,
			wantErr:    false,
		},
		{
			name:       "pretty json",
			outputPath: filepath.Join(t.TempDir(), "test.json"),
			stdout:     false,
			pretty:     true,
			wantErr:    false,
		},
		{
			name:       "invalid path",
			outputPath: "/invalid/path/that/does/not/exist/test.json",
			stdout:     false,
			pretty:     false,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := NewWriter(tt.outputPath, tt.stdout, tt.pretty)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewWriter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if w != nil {
				defer func() {
					if err := w.Close(); err != nil {
						t.Logf("Close() error: %v", err)
					}
				}()
			}
			if !tt.wantErr && w == nil {
				t.Error("NewWriter() returned nil writer without error")
			}
		})
	}
}

func TestWriterWriteEvent(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "events.json")
	w, err := NewWriter(tmpFile, false, false)
	if err != nil {
		t.Fatalf("NewWriter() failed: %v", err)
	}

	event := &tracer.ParsedEvent{
		Timestamp: "2025-01-15T14:30:22.123456789Z",
		EventType: "process_exec",
		PID:       12345,
		TGID:      12345,
		PPID:      12300,
		UID:       0,
		GID:       0,
		Comm:      "bash",
		CgroupID:  6789,
		Filename:  "/bin/bash",
	}

	w.WriteEvent(event)

	// Close file to flush data before reading
	if err := w.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	// Read and verify
	//nolint:gosec // G304: Reading temp test file
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("ReadFile() failed: %v", err)
	}

	var decoded tracer.ParsedEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}

	if decoded.EventType != event.EventType {
		t.Errorf("EventType = %v, want %v", decoded.EventType, event.EventType)
	}
	if decoded.PID != event.PID {
		t.Errorf("PID = %v, want %v", decoded.PID, event.PID)
	}
}

func TestSummaryCollectorAdd(t *testing.T) {
	s := NewSummaryCollector()

	tests := []struct {
		name       string
		event      *tracer.ParsedEvent
		wantAlerts int
	}{
		{
			name: "normal exec",
			event: &tracer.ParsedEvent{
				EventType: "process_exec",
				PID:       1000,
				Comm:      "ls",
				Filename:  "/bin/ls",
			},
			wantAlerts: 0,
		},
		{
			name: "suspicious path exec",
			event: &tracer.ParsedEvent{
				EventType: "process_exec",
				PID:       1001,
				Comm:      "suspicious",
				Filename:  "/tmp/malware",
			},
			wantAlerts: 1,
		},
		{
			name: "suspicious tool exec",
			event: &tracer.ParsedEvent{
				EventType: "process_exec",
				PID:       1002,
				Comm:      "curl",
				Filename:  "/usr/bin/curl",
			},
			wantAlerts: 1,
		},
		{
			name: "sensitive file access",
			event: &tracer.ParsedEvent{
				EventType: "file_open",
				PID:       1003,
				Comm:      "cat",
				Filename:  "/etc/shadow",
			},
			wantAlerts: 1,
		},
		{
			name: "ptrace",
			event: &tracer.ParsedEvent{
				EventType: "ptrace",
				PID:       1004,
				Comm:      "gdb",
			},
			wantAlerts: 1,
		},
		{
			name: "module_load",
			event: &tracer.ParsedEvent{
				EventType: "module_load",
				PID:       1005,
				Comm:      "insmod",
			},
			wantAlerts: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initialAlerts := len(s.alerts)
			s.Add(tt.event)
			newAlerts := len(s.alerts) - initialAlerts

			if newAlerts != tt.wantAlerts {
				t.Errorf("Add() generated %d alerts, want %d", newAlerts, tt.wantAlerts)
			}

			if s.eventCounts[tt.event.EventType] == 0 {
				t.Errorf("Event type %s not counted", tt.event.EventType)
			}
		})
	}

	if s.totalEvents != len(tests) {
		t.Errorf("totalEvents = %d, want %d", s.totalEvents, len(tests))
	}
}

func TestSummaryCollectorMmapExec(t *testing.T) {
	s := NewSummaryCollector()

	// PROT_WRITE|PROT_EXEC (0x2|0x4 = 0x6)
	prot := uint32(0x6)
	event := &tracer.ParsedEvent{
		EventType: "mmap_exec",
		PID:       2000,
		Comm:      "malware",
		Prot:      &prot,
	}

	s.Add(event)

	if len(s.alerts) != 1 {
		t.Errorf("Expected 1 alert for W+X mmap, got %d", len(s.alerts))
	}

	if len(s.alerts) > 0 && s.alerts[0].Severity != "critical" {
		t.Errorf("Expected critical severity, got %s", s.alerts[0].Severity)
	}
}

func TestSummaryCollectorPrint(t *testing.T) {
	s := NewSummaryCollector()

	// Add some test events
	events := []*tracer.ParsedEvent{
		{EventType: "process_exec", PID: 100, Comm: "test1", Filename: "/bin/test"},
		{EventType: "process_exec", PID: 101, Comm: "test2", Filename: "/tmp/malware"},
		{EventType: "file_open", PID: 102, Comm: "cat", Filename: "/etc/passwd"},
		{EventType: "net_connect", PID: 103, Comm: "curl"},
	}

	for _, ev := range events {
		s.Add(ev)
	}

	var buf bytes.Buffer
	s.Print(&buf)

	output := buf.String()

	// Check for expected content
	expectedStrings := []string{
		"azazel Summary",
		"Total events: 4",
		"Event counts:",
		"process_exec",
		"file_open",
		"net_connect",
		"Security Alerts",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Summary output missing expected string: %s", expected)
		}
	}
}

func TestCheckSuspiciousExec(t *testing.T) {
	tests := []struct {
		name       string
		filename   string
		comm       string
		wantAlert  bool
		wantDetail string
	}{
		{
			name:      "normal binary",
			filename:  "/bin/ls",
			comm:      "ls",
			wantAlert: false,
		},
		{
			name:       "tmp execution",
			filename:   "/tmp/malware",
			comm:       "malware",
			wantAlert:  true,
			wantDetail: "/tmp/malware",
		},
		{
			name:       "dev shm execution",
			filename:   "/dev/shm/exploit",
			comm:       "exploit",
			wantAlert:  true,
			wantDetail: "/dev/shm/exploit",
		},
		{
			name:       "curl tool",
			filename:   "/usr/bin/curl",
			comm:       "curl",
			wantAlert:  true,
			wantDetail: "/usr/bin/curl",
		},
		{
			name:       "python execution",
			filename:   "/usr/bin/python3",
			comm:       "python3",
			wantAlert:  true,
			wantDetail: "/usr/bin/python3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSummaryCollector()
			event := &tracer.ParsedEvent{
				EventType: "process_exec",
				PID:       1000,
				Comm:      tt.comm,
				Filename:  tt.filename,
			}

			s.checkSuspiciousExec(event)

			if tt.wantAlert && len(s.alerts) == 0 {
				t.Error("Expected alert but got none")
			}
			if !tt.wantAlert && len(s.alerts) > 0 {
				t.Errorf("Expected no alert but got %d", len(s.alerts))
			}
			if tt.wantAlert && len(s.alerts) > 0 && s.alerts[0].Detail != tt.wantDetail {
				t.Errorf("Alert detail = %s, want %s", s.alerts[0].Detail, tt.wantDetail)
			}
		})
	}
}

func TestCheckSensitiveFile(t *testing.T) {
	tests := []struct {
		name      string
		filename  string
		wantAlert bool
	}{
		{
			name:      "normal file",
			filename:  "/home/user/document.txt",
			wantAlert: false,
		},
		{
			name:      "passwd file",
			filename:  "/etc/passwd",
			wantAlert: true,
		},
		{
			name:      "shadow file",
			filename:  "/etc/shadow",
			wantAlert: true,
		},
		{
			name:      "ssh config",
			filename:  "/etc/ssh/sshd_config",
			wantAlert: true,
		},
		{
			name:      "proc self maps",
			filename:  "/proc/self/maps",
			wantAlert: true,
		},
		{
			name:      "ld preload",
			filename:  "/etc/ld.so.preload",
			wantAlert: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSummaryCollector()
			event := &tracer.ParsedEvent{
				EventType: "file_open",
				PID:       1000,
				Comm:      "cat",
				Filename:  tt.filename,
			}

			s.checkSensitiveFile(event)

			if tt.wantAlert && len(s.alerts) == 0 {
				t.Error("Expected alert but got none")
			}
			if !tt.wantAlert && len(s.alerts) > 0 {
				t.Errorf("Expected no alert but got %d", len(s.alerts))
			}
		})
	}
}

func TestCheckSensitiveFileCreation(t *testing.T) {
	tests := []struct {
		name         string
		filename     string
		flags        int32
		wantAlert    bool
		wantSeverity string
		wantMessage  string
	}{
		{
			name:      "normal file read",
			filename:  "/home/user/document.txt",
			flags:     0, // O_RDONLY
			wantAlert: false,
		},
		{
			name:         "file creation in /etc",
			filename:     "/etc/malicious.conf",
			flags:        0x241, // O_CREAT | O_WRONLY | O_CLOEXEC
			wantAlert:    true,
			wantSeverity: "high",
			wantMessage:  "file creation in sensitive directory: /etc/",
		},
		{
			name:         "file creation in /tmp",
			filename:     "/tmp/suspicious.sh",
			flags:        0x241, // O_CREAT | O_WRONLY | O_CLOEXEC
			wantAlert:    true,
			wantSeverity: "medium",
			wantMessage:  "file creation in sensitive directory: /tmp/",
		},
		{
			name:         "file creation in /boot",
			filename:     "/boot/backdoor.ko",
			flags:        0x41, // O_CREAT | O_WRONLY
			wantAlert:    true,
			wantSeverity: "high",
			wantMessage:  "file creation in sensitive directory: /boot/",
		},
		{
			name:         "file creation in /root",
			filename:     "/root/.bashrc_evil",
			flags:        0x241, // O_CREAT | O_WRONLY | O_CLOEXEC
			wantAlert:    true,
			wantSeverity: "medium",
			wantMessage:  "file creation in sensitive directory: /root/",
		},
		{
			name:         "file creation in /dev/shm",
			filename:     "/dev/shm/evil",
			flags:        0x41, // O_CREAT | O_WRONLY
			wantAlert:    true,
			wantSeverity: "medium",
			wantMessage:  "file creation in sensitive directory: /dev/shm/",
		},
		{
			name:      "file read in /etc (no alert for read)",
			filename:  "/etc/hostname",
			flags:     0, // O_RDONLY
			wantAlert: false,
		},
		{
			name:      "file creation in safe directory",
			filename:  "/home/user/newfile.txt",
			flags:     0x41, // O_CREAT | O_WRONLY
			wantAlert: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSummaryCollector()
			flags := tt.flags
			event := &tracer.ParsedEvent{
				EventType: "file_open",
				PID:       1000,
				Comm:      "touch",
				Filename:  tt.filename,
				Flags:     &flags,
			}

			s.checkSensitiveFile(event)

			if tt.wantAlert && len(s.alerts) == 0 {
				t.Error("Expected alert but got none")
				return
			}
			if !tt.wantAlert && len(s.alerts) > 0 {
				t.Errorf("Expected no alert but got %d: %+v", len(s.alerts), s.alerts)
				return
			}

			if tt.wantAlert && len(s.alerts) > 0 {
				alert := s.alerts[0]
				if alert.Severity != tt.wantSeverity {
					t.Errorf("Alert severity = %s, want %s", alert.Severity, tt.wantSeverity)
				}
				if alert.Message != tt.wantMessage {
					t.Errorf("Alert message = %s, want %s", alert.Message, tt.wantMessage)
				}
				if alert.Detail != tt.filename {
					t.Errorf("Alert detail = %s, want %s", alert.Detail, tt.filename)
				}
			}
		})
	}
}

func TestCheckNetworkActivity(t *testing.T) {
	tests := []struct {
		name         string
		event        *tracer.ParsedEvent
		wantAlert    bool
		wantSeverity string
		wantDetail   string
	}{
		{
			name: "net_connect normal port",
			event: &tracer.ParsedEvent{
				EventType: "net_connect",
				PID:       1000,
				Comm:      "curl",
				DstAddr:   "93.184.216.34",
				DstPort:   80,
				SaFamily:  "AF_INET",
			},
			wantAlert:    true,
			wantSeverity: "info",
			wantDetail:   "outbound connection to 93.184.216.34:80 (AF_INET)",
		},
		{
			name: "net_connect suspicious port 4444",
			event: &tracer.ParsedEvent{
				EventType: "net_connect",
				PID:       1001,
				Comm:      "nc",
				DstAddr:   "10.0.0.1",
				DstPort:   4444,
				SaFamily:  "AF_INET",
			},
			wantAlert:    true,
			wantSeverity: "medium",
			wantDetail:   "outbound connection to 10.0.0.1:4444 (AF_INET)",
		},
		{
			name: "net_bind",
			event: &tracer.ParsedEvent{
				EventType: "net_bind",
				PID:       1002,
				Comm:      "server",
				SrcAddr:   "0.0.0.0",
				Port:      8080,
				SaFamily:  "AF_INET",
			},
			wantAlert:    true,
			wantSeverity: "info",
			wantDetail:   "port binding 0.0.0.0:8080 (AF_INET)",
		},
		{
			name: "net_dns",
			event: &tracer.ParsedEvent{
				EventType:  "net_dns",
				PID:        1003,
				Comm:       "dig",
				ServerAddr: "8.8.8.8",
				ServerPort: 53,
			},
			wantAlert:    true,
			wantSeverity: "info",
			wantDetail:   "DNS query to DNS server 8.8.8.8:53",
		},
		{
			name: "net_sendto",
			event: &tracer.ParsedEvent{
				EventType: "net_sendto",
				PID:       1004,
				Comm:      "netcat",
				DstAddr:   "192.168.1.100",
				DstPort:   9000,
				SaFamily:  "AF_INET",
			},
			wantAlert:    true,
			wantSeverity: "info",
			wantDetail:   "data sent to 192.168.1.100:9000 (AF_INET)",
		},
		{
			name: "net_listen",
			event: &tracer.ParsedEvent{
				EventType: "net_listen",
				PID:       1005,
				Comm:      "httpd",
				Backlog:   func() *int32 { b := int32(128); return &b }(),
			},
			wantAlert:    true,
			wantSeverity: "info",
			wantDetail:   "listening on port (backlog=128)",
		},
		{
			name: "net_accept",
			event: &tracer.ParsedEvent{
				EventType: "net_accept",
				PID:       1006,
				Comm:      "nginx",
			},
			wantAlert:    true,
			wantSeverity: "info",
			wantDetail:   "incoming connection accepted",
		},
		{
			name: "net_connect IPv6",
			event: &tracer.ParsedEvent{
				EventType: "net_connect",
				PID:       1007,
				Comm:      "wget",
				DstAddr:   "2606:2800:220:1:248:1893:25c8:1946",
				DstPort:   443,
				SaFamily:  "AF_INET6",
			},
			wantAlert:    true,
			wantSeverity: "info",
			wantDetail:   "outbound connection to 2606:2800:220:1:248:1893:25c8:1946:443 (AF_INET6)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSummaryCollector()
			s.Add(tt.event)

			if tt.wantAlert && len(s.alerts) == 0 {
				t.Error("Expected alert but got none")
				return
			}
			if !tt.wantAlert && len(s.alerts) > 0 {
				t.Errorf("Expected no alert but got %d", len(s.alerts))
				return
			}

			if tt.wantAlert && len(s.alerts) > 0 {
				alert := s.alerts[len(s.alerts)-1]
				if alert.Severity != tt.wantSeverity {
					t.Errorf("Alert severity = %s, want %s", alert.Severity, tt.wantSeverity)
				}
				if alert.Detail != tt.wantDetail {
					t.Errorf("Alert detail = %s, want %s", alert.Detail, tt.wantDetail)
				}
				if alert.Message != "network activity detected" {
					t.Errorf("Alert message = %s, want 'network activity detected'", alert.Message)
				}
			}
		})
	}
}
