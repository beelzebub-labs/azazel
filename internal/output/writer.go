package output

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/azazel/internal/tracer"
)

// Writer handles JSON event output
type Writer struct {
	mu      sync.Mutex
	file    *os.File
	stdout  bool
	pretty  bool
	fileEnc *json.Encoder
	summary *SummaryCollector
}

// NewWriter creates a new event writer
func NewWriter(outputPath string, stdout bool, pretty bool) (*Writer, error) {
	w := &Writer{
		stdout:  stdout,
		pretty:  pretty,
		summary: NewSummaryCollector(),
	}

	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("create output file: %w", err)
		}
		w.file = f
		w.fileEnc = json.NewEncoder(f)
		if pretty {
			w.fileEnc.SetIndent("", "  ")
		}
	}

	return w, nil
}

// WriteEvent writes a parsed event to the configured outputs
func (w *Writer) WriteEvent(ev *tracer.ParsedEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.summary.Add(ev)

	if w.file != nil {
		if err := w.fileEnc.Encode(ev); err != nil {
			log.Printf("[azazel] Warning: failed to write event: %v", err)
		}
	}

	if w.stdout || w.file == nil {
		enc := json.NewEncoder(os.Stdout)
		if w.pretty {
			enc.SetIndent("", "  ")
		}
		enc.Encode(ev)
	}
}

// Close flushes and closes the output file
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		w.file.Sync()
		return w.file.Close()
	}
	return nil
}

// PrintSummary writes the summary to the given writer
func (w *Writer) PrintSummary(out io.Writer) {
	w.summary.Print(out)
}

// Alert represents a security alert
type Alert struct {
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Event    string `json:"event_type"`
	PID      uint32 `json:"pid"`
	Comm     string `json:"comm"`
	Detail   string `json:"detail,omitempty"`
}

// SummaryCollector collects event statistics and generates alerts
type SummaryCollector struct {
	mu          sync.Mutex
	eventCounts map[string]int
	alerts      []Alert
	totalEvents int
}

// NewSummaryCollector creates a new summary collector
func NewSummaryCollector() *SummaryCollector {
	return &SummaryCollector{
		eventCounts: make(map[string]int),
	}
}

// Suspicious paths for exec
var suspiciousExecPaths = []string{"/tmp/", "/dev/shm/", "/var/tmp/"}
var suspiciousTools = []string{"wget", "curl", "nc", "ncat", "python", "python3", "base64", "memfd:"}

// Sensitive file paths
var sensitiveFiles = []string{
	"/etc/passwd", "/etc/shadow", "/etc/sudoers",
	"/etc/ssh/", "/proc/self/maps", "/proc/self/mem",
	"/etc/ld.so.preload",
}

// Add processes an event for the summary
func (s *SummaryCollector) Add(ev *tracer.ParsedEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.totalEvents++
	s.eventCounts[ev.EventType]++

	// Check for suspicious behavior
	switch ev.EventType {
	case "process_exec":
		s.checkSuspiciousExec(ev)
	case "file_open":
		s.checkSensitiveFile(ev)
	case "ptrace":
		s.alerts = append(s.alerts, Alert{
			Severity: "high",
			Message:  "ptrace syscall detected",
			Event:    ev.EventType,
			PID:      ev.PID,
			Comm:     ev.Comm,
		})
	case "mmap_exec":
		if ev.Prot != nil && *ev.Prot&0x6 == 0x6 { // PROT_WRITE|PROT_EXEC
			s.alerts = append(s.alerts, Alert{
				Severity: "critical",
				Message:  "memory mapped as WRITE+EXEC (possible code injection/unpacking)",
				Event:    ev.EventType,
				PID:      ev.PID,
				Comm:     ev.Comm,
			})
		}
	case "module_load":
		s.alerts = append(s.alerts, Alert{
			Severity: "high",
			Message:  "kernel module loading detected",
			Event:    ev.EventType,
			PID:      ev.PID,
			Comm:     ev.Comm,
		})
	}
}

func (s *SummaryCollector) checkSuspiciousExec(ev *tracer.ParsedEvent) {
	for _, path := range suspiciousExecPaths {
		if strings.HasPrefix(ev.Filename, path) {
			s.alerts = append(s.alerts, Alert{
				Severity: "medium",
				Message:  fmt.Sprintf("execution from suspicious path: %s", ev.Filename),
				Event:    ev.EventType,
				PID:      ev.PID,
				Comm:     ev.Comm,
				Detail:   ev.Filename,
			})
			return
		}
	}
	for _, tool := range suspiciousTools {
		if strings.Contains(ev.Filename, tool) || strings.Contains(ev.Comm, tool) {
			s.alerts = append(s.alerts, Alert{
				Severity: "medium",
				Message:  fmt.Sprintf("suspicious tool execution: %s", tool),
				Event:    ev.EventType,
				PID:      ev.PID,
				Comm:     ev.Comm,
				Detail:   ev.Filename,
			})
			return
		}
	}
}

func (s *SummaryCollector) checkSensitiveFile(ev *tracer.ParsedEvent) {
	for _, path := range sensitiveFiles {
		if strings.Contains(ev.Filename, path) {
			s.alerts = append(s.alerts, Alert{
				Severity: "medium",
				Message:  fmt.Sprintf("sensitive file access: %s", ev.Filename),
				Event:    ev.EventType,
				PID:      ev.PID,
				Comm:     ev.Comm,
				Detail:   ev.Filename,
			})
			return
		}
	}
}

// Print outputs the summary to the given writer
func (s *SummaryCollector) Print(out io.Writer) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "========================================\n")
	fmt.Fprintf(out, " azazel Summary\n")
	fmt.Fprintf(out, "========================================\n")
	fmt.Fprintf(out, " Total events: %d\n", s.totalEvents)
	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, " Event counts:\n")
	for eventType, count := range s.eventCounts {
		fmt.Fprintf(out, "   %-20s %d\n", eventType, count)
	}

	if len(s.alerts) > 0 {
		fmt.Fprintf(out, "\n")
		fmt.Fprintf(out, " Security Alerts (%d):\n", len(s.alerts))
		for _, alert := range s.alerts {
			fmt.Fprintf(out, "   [%s] %s (pid=%d comm=%s)\n",
				strings.ToUpper(alert.Severity), alert.Message, alert.PID, alert.Comm)
			if alert.Detail != "" {
				fmt.Fprintf(out, "          detail: %s\n", alert.Detail)
			}
		}
	} else {
		fmt.Fprintf(out, "\n No security alerts.\n")
	}
	fmt.Fprintf(out, "========================================\n")
}
