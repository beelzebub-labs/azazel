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
func NewWriter(outputPath string, stdout, pretty bool) (*Writer, error) {
	w := &Writer{
		stdout:  stdout,
		pretty:  pretty,
		summary: NewSummaryCollector(),
	}

	if outputPath != "" {
		//nolint:gosec // G304: Output path is provided by user via CLI flag
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
		if err := enc.Encode(ev); err != nil {
			log.Printf("[azazel] Warning: failed to write to stdout: %v", err)
		}
	}
}

// Close flushes and closes the output file
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		if err := w.file.Sync(); err != nil {
			log.Printf("[azazel] Warning: failed to sync file: %v", err)
		}
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

// Sensitive file paths for reading
var sensitiveFiles = []string{
	"/etc/passwd", "/etc/shadow", "/etc/sudoers",
	"/etc/ssh/", "/proc/self/maps", "/proc/self/mem",
	"/etc/ld.so.preload",
}

// Sensitive directories for file creation
var sensitiveCreateDirs = []string{
	"/etc/",
	"/boot/",
	"/root/",
	"/tmp/",
	"/var/tmp/",
	"/dev/shm/",
}

// O_CREAT flag (file creation)
const O_CREAT = 0x40

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
	case "net_connect":
		s.checkNetworkActivity(ev, "outbound connection")
	case "net_bind":
		s.checkNetworkActivity(ev, "port binding")
	case "net_listen":
		s.checkNetworkActivity(ev, "listening on port")
	case "net_sendto":
		s.checkNetworkActivity(ev, "data sent to")
	case "net_dns":
		s.checkNetworkActivity(ev, "DNS query")
	case "net_accept":
		s.checkNetworkActivity(ev, "incoming connection accepted")
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
	// Check for reading sensitive files
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

	// Check for file creation in sensitive directories
	if ev.Flags != nil && (*ev.Flags&O_CREAT) != 0 {
		for _, dir := range sensitiveCreateDirs {
			if strings.HasPrefix(ev.Filename, dir) {
				severity := "medium"
				// /etc is more critical than /tmp
				if strings.HasPrefix(ev.Filename, "/etc/") || strings.HasPrefix(ev.Filename, "/boot/") {
					severity = "high"
				}
				s.alerts = append(s.alerts, Alert{
					Severity: severity,
					Message:  fmt.Sprintf("file creation in sensitive directory: %s", dir),
					Event:    ev.EventType,
					PID:      ev.PID,
					Comm:     ev.Comm,
					Detail:   ev.Filename,
				})
				return
			}
		}
	}
}

func (s *SummaryCollector) checkNetworkActivity(ev *tracer.ParsedEvent, action string) {
	detail, severity := s.formatNetworkDetail(ev, action)
	if detail == "" {
		return
	}

	s.alerts = append(s.alerts, Alert{
		Severity: severity,
		Message:  "network activity detected",
		Event:    ev.EventType,
		PID:      ev.PID,
		Comm:     ev.Comm,
		Detail:   detail,
	})
}

func (s *SummaryCollector) formatNetworkDetail(ev *tracer.ParsedEvent, action string) (detail, severity string) {
	severity = "info"

	switch ev.EventType {
	case "net_connect":
		detail, severity = formatNetConnect(ev, action)
	case "net_bind":
		detail = formatNetBind(ev, action)
	case "net_listen":
		detail = formatNetListen(ev, action)
	case "net_sendto":
		detail = formatNetSendto(ev, action)
	case "net_dns":
		detail = formatNetDNS(ev, action)
	case "net_accept":
		detail = action
	}

	return detail, severity
}

func formatNetConnect(ev *tracer.ParsedEvent, action string) (detail, severity string) {
	severity = "info"
	if ev.DstAddr == "" || ev.DstPort == 0 {
		return "", severity
	}

	detail = fmt.Sprintf("%s to %s:%d (%s)", action, ev.DstAddr, ev.DstPort, ev.SaFamily)
	// Highlight connections to suspicious ports
	if isSuspiciousPort(ev.DstPort) {
		severity = "medium"
	}
	return detail, severity
}

func formatNetBind(ev *tracer.ParsedEvent, action string) string {
	if ev.SrcAddr == "" || ev.Port == 0 {
		return ""
	}
	return fmt.Sprintf("%s %s:%d (%s)", action, ev.SrcAddr, ev.Port, ev.SaFamily)
}

func formatNetListen(ev *tracer.ParsedEvent, action string) string {
	if ev.Backlog != nil {
		return fmt.Sprintf("%s (backlog=%d)", action, *ev.Backlog)
	}
	return action
}

func formatNetSendto(ev *tracer.ParsedEvent, action string) string {
	if ev.DstAddr == "" || ev.DstPort == 0 {
		return ""
	}
	return fmt.Sprintf("%s %s:%d (%s)", action, ev.DstAddr, ev.DstPort, ev.SaFamily)
}

func formatNetDNS(ev *tracer.ParsedEvent, action string) string {
	if ev.ServerAddr == "" || ev.ServerPort == 0 {
		return ""
	}
	return fmt.Sprintf("%s to DNS server %s:%d", action, ev.ServerAddr, ev.ServerPort)
}

func isSuspiciousPort(port uint16) bool {
	return port == 4444 || port == 5555 || port == 6666 || port == 31337
}

// Print outputs the summary to the given writer
func (s *SummaryCollector) Print(out io.Writer) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, _ = fmt.Fprintf(out, "\n")
	_, _ = fmt.Fprintf(out, "========================================\n")
	_, _ = fmt.Fprintf(out, " azazel Summary\n")
	_, _ = fmt.Fprintf(out, "========================================\n")
	_, _ = fmt.Fprintf(out, " Total events: %d\n", s.totalEvents)
	_, _ = fmt.Fprintf(out, "\n")
	_, _ = fmt.Fprintf(out, " Event counts:\n")
	for eventType, count := range s.eventCounts {
		_, _ = fmt.Fprintf(out, "   %-20s %d\n", eventType, count)
	}

	if len(s.alerts) > 0 {
		_, _ = fmt.Fprintf(out, "\n")
		_, _ = fmt.Fprintf(out, " Security Alerts (%d):\n", len(s.alerts))
		for _, alert := range s.alerts {
			_, _ = fmt.Fprintf(out, "   [%s] %s (pid=%d comm=%s)\n",
				strings.ToUpper(alert.Severity), alert.Message, alert.PID, alert.Comm)
			if alert.Detail != "" {
				_, _ = fmt.Fprintf(out, "          detail: %s\n", alert.Detail)
			}
		}
	} else {
		_, _ = fmt.Fprintf(out, "\n No security alerts.\n")
	}
	_, _ = fmt.Fprintf(out, "========================================\n")
}
