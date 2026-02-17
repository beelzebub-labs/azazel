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
				defer w.Close()
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
	defer w.Close()

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
	w.Close()

	// Read and verify
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
