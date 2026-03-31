package tracer

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// bootTimeOffset is the offset between monotonic clock and wall clock.
// bpf_ktime_get_ns() returns monotonic time; we add this offset to get wall time.
var bootTimeOffset int64

func init() {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err == nil {
		mono := ts.Nano()
		wall := time.Now().UnixNano()
		bootTimeOffset = wall - mono
	}
}

// Event type constants — must match BPF C side
const (
	EventProcessExec    uint32 = 1
	EventProcessExit    uint32 = 2
	EventFileOpen       uint32 = 3
	EventFileWrite      uint32 = 4
	EventFileRead       uint32 = 5
	EventFileUnlink     uint32 = 6
	EventNetConnect     uint32 = 7
	EventNetAccept      uint32 = 8
	EventNetBind        uint32 = 9
	EventNetSendto      uint32 = 10
	EventNetRecvfrom    uint32 = 11
	EventNetDNS         uint32 = 12
	EventSyscallGeneric uint32 = 13
	EventProcessClone   uint32 = 14
	EventFileRename     uint32 = 15
	EventNetListen      uint32 = 16
	EventMmapExec       uint32 = 17
	EventPtrace         uint32 = 18
	EventModuleLoad     uint32 = 19
)

const (
	MaxFilenameLen = 256
	MaxArgsLen     = 256
	MaxCommLen     = 16
)

// EventTypeName returns the human-readable name for an event type
//
//nolint:gocyclo // Simple switch statement for event type mapping
func EventTypeName(t uint32) string {
	switch t {
	case EventProcessExec:
		return "process_exec"
	case EventProcessExit:
		return "process_exit"
	case EventFileOpen:
		return "file_open"
	case EventFileWrite:
		return "file_write"
	case EventFileRead:
		return "file_read"
	case EventFileUnlink:
		return "file_unlink"
	case EventNetConnect:
		return "net_connect"
	case EventNetAccept:
		return "net_accept"
	case EventNetBind:
		return "net_bind"
	case EventNetSendto:
		return "net_sendto"
	case EventNetRecvfrom:
		return "net_recvfrom"
	case EventNetDNS:
		return "net_dns"
	case EventSyscallGeneric:
		return "syscall_generic"
	case EventProcessClone:
		return "process_clone"
	case EventFileRename:
		return "file_rename"
	case EventNetListen:
		return "net_listen"
	case EventMmapExec:
		return "mmap_exec"
	case EventPtrace:
		return "ptrace"
	case EventModuleLoad:
		return "module_load"
	default:
		return fmt.Sprintf("unknown_%d", t)
	}
}

// Raw BPF structs — must match C structs byte-for-byte

type RawEventHeader struct {
	TimestampNs uint64
	Pid         uint32
	Tgid        uint32
	Uid         uint32
	Gid         uint32
	Ppid        uint32
	EventType   uint32
	CgroupID    uint64
	Comm        [MaxCommLen]byte
}

type RawProcessExecEvent struct {
	Hdr      RawEventHeader
	Filename [MaxFilenameLen]byte
	Args     [MaxArgsLen]byte
}

type RawProcessExitEvent struct {
	Hdr      RawEventHeader
	ExitCode int32
	Pad      uint32
}

type RawFileOpenEvent struct {
	Hdr      RawEventHeader
	Filename [MaxFilenameLen]byte
	Flags    int32
	Pad      uint32
}

type RawFileWriteEvent struct {
	Hdr   RawEventHeader
	Fd    uint32
	Pad0  uint32 // padding for alignment
	Count uint64
	Pad   uint32
	Pad1  uint32 // trailing padding
}

type RawFileReadEvent struct {
	Hdr   RawEventHeader
	Fd    uint32
	Pad0  uint32
	Count uint64
	Pad   uint32
	Pad1  uint32
}

type RawFileUnlinkEvent struct {
	Hdr      RawEventHeader
	Filename [MaxFilenameLen]byte
}

type RawNetConnectEvent struct {
	Hdr      RawEventHeader
	SaFamily uint16
	DstPort  uint16
	DstAddr4 uint32
	DstAddr6 [16]byte
	Pad      uint32
}

type RawNetAcceptEvent struct {
	Hdr RawEventHeader
}

type RawNetBindEvent struct {
	Hdr      RawEventHeader
	SaFamily uint16
	Port     uint16
	Addr4    uint32
	Addr6    [16]byte
	Pad      uint32
}

type RawNetSendtoEvent struct {
	Hdr      RawEventHeader
	SaFamily uint16
	DstPort  uint16
	DstAddr4 uint32
	DstAddr6 [16]byte
	Pad      uint32
}

type RawNetDNSEvent struct {
	Hdr         RawEventHeader
	ServerAddr4 uint32
	ServerPort  uint16
	Pad         uint16
}

type RawProcessCloneEvent struct {
	Hdr        RawEventHeader
	CloneFlags uint64
}

type RawFileRenameEvent struct {
	Hdr     RawEventHeader
	OldName [MaxFilenameLen]byte
}

type RawNetListenEvent struct {
	Hdr     RawEventHeader
	Backlog int32
	Pad     uint32
}

type RawMmapExecEvent struct {
	Hdr   RawEventHeader
	Addr  uint64
	Len   uint64
	Prot  uint32
	Flags uint32
}

type RawPtraceEvent struct {
	Hdr       RawEventHeader
	Request   uint32
	TargetPid uint32
}

type RawModuleLoadEvent struct {
	Hdr   RawEventHeader
	Fd    int32
	Flags int32
}

// Parsed Go structs for JSON output

type ParsedEvent struct {
	Timestamp   string `json:"timestamp"`
	EventType   string `json:"event_type"`
	PID         uint32 `json:"pid"`
	TGID        uint32 `json:"tgid"`
	PPID        uint32 `json:"ppid"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	Comm        string `json:"comm"`
	CgroupID    uint64 `json:"cgroup_id"`
	ContainerID string `json:"container_id,omitempty"`

	// Process fields
	Filename string `json:"filename,omitempty"`
	Args     string `json:"args,omitempty"`
	ExitCode *int32 `json:"exit_code,omitempty"`

	// File fields
	Flags   *int32  `json:"flags,omitempty"`
	Fd      *uint32 `json:"fd,omitempty"`
	Count   *uint64 `json:"count,omitempty"`
	OldName string  `json:"oldname,omitempty"`

	// Network fields
	SaFamily string `json:"sa_family,omitempty"`
	DstAddr  string `json:"dst_addr,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	SrcAddr  string `json:"src_addr,omitempty"`
	Port     uint16 `json:"port,omitempty"`
	Backlog  *int32 `json:"backlog,omitempty"`

	// DNS fields
	ServerAddr string `json:"server_addr,omitempty"`
	ServerPort uint16 `json:"server_port,omitempty"`

	// Security fields
	CloneFlags  *uint64 `json:"clone_flags,omitempty"`
	Addr        *uint64 `json:"addr,omitempty"`
	Len         *uint64 `json:"len,omitempty"`
	Prot        *uint32 `json:"prot,omitempty"`
	MmapFlags   *uint32 `json:"mmap_flags,omitempty"`
	Request     *uint32 `json:"request,omitempty"`
	TargetPid   *uint32 `json:"target_pid,omitempty"`
	ModuleFd    *int32  `json:"module_fd,omitempty"`
	ModuleFlags *int32  `json:"module_flags,omitempty"`
}

// RawEventHeaderSize is used for initial event type detection
var RawEventHeaderSize = int(unsafe.Sizeof(RawEventHeader{}))

// nullTermStr extracts a null-terminated string from a byte slice
func nullTermStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// ipv4Str converts a uint32 to an IPv4 string
func ipv4Str(addr uint32) string {
	return net.IPv4(
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24),
	).String()
}

// ipv6Str converts a [16]byte to an IPv6 string
func ipv6Str(addr [16]byte) string {
	ip := net.IP(addr[:])
	return ip.String()
}

// saFamilyStr converts address family number to string
func saFamilyStr(f uint16) string {
	switch f {
	case 2:
		return "AF_INET"
	case 10:
		return "AF_INET6"
	default:
		return fmt.Sprintf("AF_%d", f)
	}
}

// parseHeader extracts the common header from raw bytes
func parseHeader(hdr *RawEventHeader) ParsedEvent {
	//nolint:gosec // G115: Timestamp conversion is safe, comes from kernel
	wallNs := int64(hdr.TimestampNs) + bootTimeOffset
	return ParsedEvent{
		Timestamp: time.Unix(0, wallNs).UTC().Format(time.RFC3339Nano),
		EventType: EventTypeName(hdr.EventType),
		PID:       hdr.Pid,
		TGID:      hdr.Tgid,
		PPID:      hdr.Ppid,
		UID:       hdr.Uid,
		GID:       hdr.Gid,
		Comm:      nullTermStr(hdr.Comm[:]),
		CgroupID:  hdr.CgroupID,
	}
}

// ParseEvent takes raw bytes from the ring buffer and returns a parsed event
//
//nolint:gocyclo // Simple switch statement for event parsing
func ParseEvent(data []byte) (*ParsedEvent, error) {
	if len(data) < RawEventHeaderSize {
		return nil, fmt.Errorf("data too short for header: %d bytes", len(data))
	}

	// Read header to determine event type
	var hdr RawEventHeader
	if err := binary.Read(bytesReader(data[:RawEventHeaderSize]), binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	switch hdr.EventType {
	case EventProcessExec:
		return parseProcessExec(data)
	case EventProcessExit:
		return parseProcessExit(data)
	case EventFileOpen:
		return parseFileOpen(data)
	case EventFileWrite:
		return parseFileWrite(data)
	case EventFileRead:
		return parseFileRead(data)
	case EventFileUnlink:
		return parseFileUnlink(data)
	case EventNetConnect:
		return parseNetConnect(data)
	case EventNetAccept:
		return parseNetAccept(data)
	case EventNetBind:
		return parseNetBind(data)
	case EventNetSendto:
		return parseNetSendto(data)
	case EventNetDNS:
		return parseNetDNS(data)
	case EventProcessClone:
		return parseProcessClone(data)
	case EventFileRename:
		return parseFileRename(data)
	case EventNetListen:
		return parseNetListen(data)
	case EventMmapExec:
		return parseMmapExec(data)
	case EventPtrace:
		return parsePtrace(data)
	case EventModuleLoad:
		return parseModuleLoad(data)
	default:
		ev := parseHeader(&hdr)
		return &ev, nil
	}
}

func parseProcessExec(data []byte) (*ParsedEvent, error) {
	var raw RawProcessExecEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	ev.Filename = nullTermStr(raw.Filename[:])
	ev.Args = nullTermStr(raw.Args[:])
	return &ev, nil
}

func parseProcessExit(data []byte) (*ParsedEvent, error) {
	var raw RawProcessExitEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	code := raw.ExitCode
	ev.ExitCode = &code
	return &ev, nil
}

func parseFileOpen(data []byte) (*ParsedEvent, error) {
	var raw RawFileOpenEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	ev.Filename = nullTermStr(raw.Filename[:])
	flags := raw.Flags
	ev.Flags = &flags
	return &ev, nil
}

func parseFileWrite(data []byte) (*ParsedEvent, error) {
	var raw RawFileWriteEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	fd := raw.Fd
	ev.Fd = &fd
	count := raw.Count
	ev.Count = &count
	return &ev, nil
}

func parseFileRead(data []byte) (*ParsedEvent, error) {
	var raw RawFileReadEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	fd := raw.Fd
	ev.Fd = &fd
	count := raw.Count
	ev.Count = &count
	return &ev, nil
}

func parseFileUnlink(data []byte) (*ParsedEvent, error) {
	var raw RawFileUnlinkEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	ev.Filename = nullTermStr(raw.Filename[:])
	return &ev, nil
}

func parseNetConnect(data []byte) (*ParsedEvent, error) {
	var raw RawNetConnectEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	ev.SaFamily = saFamilyStr(raw.SaFamily)
	ev.DstPort = raw.DstPort
	if raw.SaFamily == 2 {
		ev.DstAddr = ipv4Str(raw.DstAddr4)
	} else {
		ev.DstAddr = ipv6Str(raw.DstAddr6)
	}
	return &ev, nil
}

func parseNetAccept(data []byte) (*ParsedEvent, error) {
	var raw RawNetAcceptEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	return &ev, nil
}

func parseNetBind(data []byte) (*ParsedEvent, error) {
	var raw RawNetBindEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	ev.SaFamily = saFamilyStr(raw.SaFamily)
	ev.Port = raw.Port
	if raw.SaFamily == 2 {
		ev.SrcAddr = ipv4Str(raw.Addr4)
	} else {
		ev.SrcAddr = ipv6Str(raw.Addr6)
	}
	return &ev, nil
}

func parseNetSendto(data []byte) (*ParsedEvent, error) {
	var raw RawNetSendtoEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	ev.SaFamily = saFamilyStr(raw.SaFamily)
	ev.DstPort = raw.DstPort
	if raw.SaFamily == 2 {
		ev.DstAddr = ipv4Str(raw.DstAddr4)
	} else {
		ev.DstAddr = ipv6Str(raw.DstAddr6)
	}
	return &ev, nil
}

func parseNetDNS(data []byte) (*ParsedEvent, error) {
	var raw RawNetDNSEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	ev.ServerAddr = ipv4Str(raw.ServerAddr4)
	ev.ServerPort = raw.ServerPort
	return &ev, nil
}

func parseProcessClone(data []byte) (*ParsedEvent, error) {
	var raw RawProcessCloneEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	flags := raw.CloneFlags
	ev.CloneFlags = &flags
	return &ev, nil
}

func parseFileRename(data []byte) (*ParsedEvent, error) {
	var raw RawFileRenameEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	ev.OldName = nullTermStr(raw.OldName[:])
	return &ev, nil
}

func parseNetListen(data []byte) (*ParsedEvent, error) {
	var raw RawNetListenEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	backlog := raw.Backlog
	ev.Backlog = &backlog
	return &ev, nil
}

func parseMmapExec(data []byte) (*ParsedEvent, error) {
	var raw RawMmapExecEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	ev.Addr = &raw.Addr
	ev.Len = &raw.Len
	ev.Prot = &raw.Prot
	ev.MmapFlags = &raw.Flags
	return &ev, nil
}

func parsePtrace(data []byte) (*ParsedEvent, error) {
	var raw RawPtraceEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	ev.Request = &raw.Request
	ev.TargetPid = &raw.TargetPid
	return &ev, nil
}

func parseModuleLoad(data []byte) (*ParsedEvent, error) {
	var raw RawModuleLoadEvent
	if err := readStruct(data, &raw); err != nil {
		return nil, err
	}
	ev := parseHeader(&raw.Hdr)
	ev.ModuleFd = &raw.Fd
	ev.ModuleFlags = &raw.Flags
	return &ev, nil
}

// readStruct reads binary data into a struct, using only as many bytes as needed
func readStruct(data []byte, v interface{}) error {
	size := binary.Size(v)
	if len(data) < size {
		// Try to read what we have — padding may cause size mismatches
		return binary.Read(bytesReader(data), binary.LittleEndian, v)
	}
	return binary.Read(bytesReader(data[:size]), binary.LittleEndian, v)
}

type bytesReaderT struct {
	data []byte
	pos  int
}

func bytesReader(data []byte) *bytesReaderT {
	return &bytesReaderT{data: data}
}

func (r *bytesReaderT) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
