package tracer

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate sh ./generate.sh

// EventHandler is called for each parsed event
type EventHandler func(ev *ParsedEvent)

// Tracer is the core eBPF tracer
type Tracer struct {
	objs    tracerObjects
	links   []link.Link
	reader  *ringbuf.Reader
	handler EventHandler
	verbose bool
}

// Config holds tracer configuration
type Config struct {
	ContainerIDs []string
	Verbose      bool
	Handler      EventHandler
}

// New creates and initializes a new tracer
func New(cfg Config) (*Tracer, error) {
	// Remove memlock limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	t := &Tracer{
		handler: cfg.Handler,
		verbose: cfg.Verbose,
	}

	// Load BPF objects
	if err := loadTracerObjects(&t.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load BPF objects (verifier): %+v", ve)
		}
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	// Set self PID to filter out tracer's own events (prevents feedback loops)
	selfPidKey := uint32(1) // CONFIG_SELF_PID
	//nolint:gosec // G115: PID conversion is safe, always positive
	selfPidVal := uint64(os.Getpid())
	if err := t.objs.TracerConfig.Put(selfPidKey, selfPidVal); err != nil {
		log.Printf("[azazel] Warning: could not set self-PID filter: %v", err)
	} else {
		log.Printf("[azazel] Self-PID filter set: %d", selfPidVal)
	}

	// Set up container filter if specified
	if len(cfg.ContainerIDs) > 0 {
		if err := t.setupContainerFilter(cfg.ContainerIDs); err != nil {
			_ = t.objs.Close()
			return nil, fmt.Errorf("setup container filter: %w", err)
		}
	}

	// Attach all programs
	if err := t.attachPrograms(); err != nil {
		t.Close()
		return nil, fmt.Errorf("attach programs: %w", err)
	}

	// Open ring buffer reader
	reader, err := ringbuf.NewReader(t.objs.Events)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	t.reader = reader

	return t, nil
}

// setupContainerFilter configures the BPF maps to filter by container
func (t *Tracer) setupContainerFilter(containerIDs []string) error {
	// Import here to avoid circular dependency
	// We use the config map index 0 to enable filtering
	key := uint32(0)
	val := uint64(1) // enable filter
	if err := t.objs.TracerConfig.Put(key, val); err != nil {
		return fmt.Errorf("set config filter_enabled: %w", err)
	}

	// For each container, resolve its cgroup ID and add to filter map
	for _, id := range containerIDs {
		log.Printf("[azazel] Note: container filtering for %s requires cgroup ID resolution at runtime", id)
		// The actual cgroup ID resolution happens via the container package
		// For now, we store the config. Runtime resolution happens in cmd/root.go
	}

	return nil
}

// AddCgroupFilter adds a cgroup ID to the filter map
func (t *Tracer) AddCgroupFilter(cgroupID uint64) error {
	val := uint8(1)
	return t.objs.ContainerFilter.Put(cgroupID, val)
}

// attachPrograms attaches all BPF programs to their hooks
func (t *Tracer) attachPrograms() error {
	type attachment struct {
		name string
		fn   func() (link.Link, error)
	}

	attachments := []attachment{
		{"sys_enter_execve", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_execve", t.objs.TraceExecve, nil)
		}},
		{"sched_process_exit", func() (link.Link, error) {
			return link.Tracepoint("sched", "sched_process_exit", t.objs.TraceProcessExit, nil)
		}},
		{"sys_enter_clone", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_clone", t.objs.TraceClone, nil)
		}},
		{"sys_enter_openat", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_openat", t.objs.TraceOpenat, nil)
		}},
		{"sys_enter_write", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_write", t.objs.TraceWrite, nil)
		}},
		{"sys_enter_read", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_read", t.objs.TraceRead, nil)
		}},
		{"sys_enter_unlinkat", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_unlinkat", t.objs.TraceUnlinkat, nil)
		}},
		{"sys_enter_renameat2", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_renameat2", t.objs.TraceRenameat2, nil)
		}},
		{"sys_enter_connect", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_connect", t.objs.TraceConnect, nil)
		}},
		{"sys_enter_accept4", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_accept4", t.objs.TraceAccept4, nil)
		}},
		{"sys_enter_bind", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_bind", t.objs.TraceBind, nil)
		}},
		{"sys_enter_listen", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_listen", t.objs.TraceListen, nil)
		}},
		{"sys_enter_sendto", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_sendto", t.objs.TraceSendto, nil)
		}},
		{"udp_sendmsg (kprobe)", func() (link.Link, error) {
			return link.Kprobe("udp_sendmsg", t.objs.TraceUdpSendmsg, nil)
		}},
		{"sys_enter_mmap", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_mmap", t.objs.TraceMmap, nil)
		}},
		{"sys_enter_ptrace", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_ptrace", t.objs.TracePtrace, nil)
		}},
		{"sys_enter_finit_module", func() (link.Link, error) {
			return link.Tracepoint("syscalls", "sys_enter_finit_module", t.objs.TraceFinitModule, nil)
		}},
	}

	for _, a := range attachments {
		l, err := a.fn()
		if err != nil {
			log.Printf("[azazel] Warning: failed to attach %s: %v", a.name, err)
			continue
		}
		t.links = append(t.links, l)
		if t.verbose {
			log.Printf("[azazel] Attached: %s", a.name)
		}
	}

	if len(t.links) == 0 {
		return fmt.Errorf("no programs could be attached")
	}

	log.Printf("[azazel] Attached %d/%d programs", len(t.links), len(attachments))
	return nil
}

// Run starts reading events from the ring buffer until context is canceled
func (t *Tracer) Run(ctx context.Context) error {
	log.Printf("[azazel] Started reading events...")

	go func() {
		<-ctx.Done()
		// Detach BPF programs first to stop generating new events
		for _, l := range t.links {
			_ = l.Close()
		}
		t.links = nil
		// Pause to let ring buffer drain remaining events
		time.Sleep(2 * time.Second)
		_ = t.reader.Close()
	}()

	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("[azazel] Warning: ring buffer read error: %v", err)
			continue
		}

		ev, err := ParseEvent(record.RawSample)
		if err != nil {
			if t.verbose {
				log.Printf("[azazel] Warning: parse event error: %v", err)
			}
			continue
		}

		if t.handler != nil {
			t.handler(ev)
		}
	}
}

// Close releases all resources
func (t *Tracer) Close() {
	if t.reader != nil {
		_ = t.reader.Close()
	}
	// links may have been closed in Run's shutdown goroutine
	for _, l := range t.links {
		_ = l.Close()
	}
	t.links = nil
	_ = t.objs.Close()
}
