<p align="center">
  <img src="https://img.shields.io/badge/eBPF-powered-blueviolet?style=for-the-badge" alt="eBPF powered" />
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.24+" />
  <img src="https://img.shields.io/badge/Linux-5.8+-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Linux 5.8+" />
  <img src="https://img.shields.io/badge/License-GPL--2.0-green?style=for-the-badge" alt="License GPL-2.0" />
</p>

![Image](assets/azazel.png)

# Azazel

****

A lightweight eBPF-based runtime security tracer purpose-built for **malware analysis sandboxes**. Drop a sample into an isolated container, and Azazel captures every syscall, file touch, network connection, and suspicious behavior — then hands you a clean JSON stream of everything that happened.

Designed from scratch for sandbox forensics rather than general-purpose runtime security.

---

## Architecture

![Image](assets/azazel_architectures.png)

## What it captures

| Category | Events | Details |
|----------|--------|---------|
| **Process** | `process_exec`, `process_exit`, `process_clone` | Full process tree: filename, argv, exit codes, clone flags, parent PID |
| **File** | `file_open`, `file_write`, `file_read`, `file_unlink`, `file_rename` | Pathnames, flags, byte counts |
| **Network** | `net_connect`, `net_bind`, `net_listen`, `net_accept`, `net_sendto`, `net_dns` | IPv4/IPv6 addresses, ports, DNS detection via kprobe on `udp_sendmsg` |
| **Security** | `mmap_exec`, `ptrace`, `module_load` | W+X memory mappings, process injection attempts, kernel module loading |

**19 hook points** total — tracepoints on syscall entry + a kprobe for DNS detection.

---

## Why Azazel?

- **Sandbox-first** — built to trace isolated containers, with cgroup-based filtering to capture only the malware you're analyzing
- **Zero dependencies at runtime** — single static Go binary, no agents or daemons
- **CO-RE** — Compile Once, Run Everywhere via BTF and `vmlinux.h`, works across kernel versions without recompilation
- **JSON-native** — NDJSON output (one event per line) ready for `jq`, Elasticsearch, Splunk, or your own pipeline
- **Built-in heuristics** — automatic alerts for exec from `/tmp`, sensitive file access (`/etc/shadow`, `/proc/self/mem`), ptrace, W+X mmap, and kernel module loading

---

## Quick start

### Prerequisites

- Linux kernel **5.8+** with `CONFIG_DEBUG_INFO_BTF=y`
- Docker (for the dev container and sandboxing)
- That's it

Verify your kernel:

```bash
# BTF support (required)
ls /sys/kernel/btf/vmlinux

# Kernel version
uname -r
```

### Build with Docker (recommended)

```bash
# Clone
git clone https://github.com/beelzebub-labs/azazel.git
cd azazel

# Build the dev container
make docker-dev

# Enter it (privileged, with host PID/cgroup namespace)
make docker-dev-run

# Inside the container:
make vmlinux    # Generate kernel type definitions
make generate   # Compile BPF C → Go bindings
make build      # Build the binary
```

### Run

```bash
# Trace everything, output to stdout
sudo ./bin/azazel

# Trace everything, save to file with pretty JSON
sudo ./bin/azazel --output events.json --pretty

# Trace only a specific container
sudo ./bin/azazel --container <container_id> --output events.json

# List running containers
sudo ./bin/azazel list-containers
```

### Run the test suite

```bash
# Inside the dev container
make test
```

This builds the binary, starts the tracer, runs a malware behavior simulator, then validates that all expected event types were captured.

---

## Output format

Every event is a single JSON line (NDJSON):

```json
{
  "timestamp": "2025-01-15T14:30:22.123456789Z",
  "event_type": "process_exec",
  "pid": 12345,
  "tgid": 12345,
  "ppid": 12300,
  "uid": 0,
  "gid": 0,
  "comm": "bash",
  "cgroup_id": 6789,
  "container_id": "a1b2c3d4e5f6",
  "filename": "/tmp/suspicious_binary",
  "args": "/tmp/suspicious_binary"
}
```

```json
{
  "timestamp": "2025-01-15T14:30:22.234567890Z",
  "event_type": "net_connect",
  "pid": 12345,
  "tgid": 12345,
  "ppid": 12300,
  "uid": 0,
  "gid": 0,
  "comm": "curl",
  "cgroup_id": 6789,
  "container_id": "a1b2c3d4e5f6",
  "sa_family": "AF_INET",
  "dst_addr": "93.184.216.34",
  "dst_port": 443
}
```

When the tracer shuts down (Ctrl+C or SIGTERM), it prints a summary to stderr:

```
========================================
 Azazel Summary
========================================
 Total events: 1847

 Event counts:
   file_open             892
   file_write            312
   process_exec           47
   net_connect            23
   ...

 Security Alerts (3):
   [MEDIUM] execution from suspicious path: /tmp/suspicious_binary (pid=12345 comm=bash)
   [MEDIUM] sensitive file access: /etc/shadow (pid=12346 comm=cat)
   [CRITICAL] memory mapped as WRITE+EXEC (possible code injection/unpacking) (pid=12347 comm=malware)
========================================
```

---

## Sandbox setup with Docker Compose

The included `docker-compose.yml` sets up a complete analysis environment:

![Image](assets/sandbox_setup.png)


```bash
# Start the sandbox
docker compose up -d

# Copy a sample into the sandbox
docker cp ./samples/malware.elf sandbox:/tmp/sample

# Execute it
docker exec sandbox /tmp/sample

# Events are written to ./output/events.json
cat output/events.json | jq .
```

### Automated analysis

```bash
# Analyze a sample end-to-end: hash → trace → report
sudo ./analyze.sh ./samples/malware.elf 30
```

This produces:
- `output/events_<timestamp>.json` — raw event stream
- `output/report_<timestamp>.md` — Markdown report with hashes, event summary, network connections, and security alerts

---

## CLI reference

```
Usage:
  azazel [flags]
  azazel [command]

Commands:
  list-containers   List running containers
  version           Print version

Flags:
  -c, --container strings   Container ID(s) to filter (can specify multiple)
  -o, --output string       Output file path (default: stdout)
      --pretty              Pretty-print JSON output
      --stdout              Also print to stdout when --output is set
  -v, --verbose             Verbose logging
      --no-summary          Disable summary on exit
  -h, --help                Help
```

---

### Project structure

```
azazel/
├── main.go                          # Entry point
├── cmd/root.go                      # CLI (cobra)
├── bpf/tracer.bpf.c                 # All eBPF programs (single file)
├── internal/
│   ├── tracer/
│   │   ├── tracer.go                # Core: load, attach, read ring buffer
│   │   └── events.go                # Event types, structs, parsing
│   ├── container/
│   │   └── resolver.go              # cgroup → container ID resolution
│   └── output/
│       └── writer.go                # JSON output + heuristic alerts
├── test/
│   ├── simulate_malware.sh          # Malware behavior simulator
│   └── run_tests.sh                 # Automated test suite
├── Dockerfile                       # Production multi-stage build
├── Dockerfile.dev                   # Dev container with build deps
├── docker-compose.yml               # Full sandbox environment
├── analyze.sh                       # Automated analysis script
└── Makefile                         # Build system
```

---

## Heuristic alerts

Azazel flags suspicious behavior automatically:

| Alert | Severity | Trigger |
|-------|----------|---------|
| Suspicious exec path | Medium | Execution from `/tmp/`, `/dev/shm/`, `/var/tmp/` |
| Suspicious tool | Medium | `wget`, `curl`, `nc`, `python`, `base64`, `memfd:` |
| Sensitive file access | Medium | `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/`, `/proc/self/maps`, `/proc/self/mem`, `/etc/ld.so.preload` |
| Ptrace | High | Any `ptrace` syscall (process injection / debugging) |
| Kernel module load | High | Any `finit_module` syscall |
| W+X mmap | Critical | Memory mapped as WRITE+EXEC simultaneously (code injection, unpacking) |

---

## Developing

### Dev container

Everything builds and runs inside a single Docker container with Go, clang, libbpf, and bpftool:

```bash
make docker-dev          # Build the dev image
make docker-dev-run      # Enter it (privileged + host namespaces)
```

### Build workflow

```bash
# Inside the dev container:
make vmlinux             # Generate vmlinux.h from host kernel BTF
make generate            # bpf2go: compile BPF C → Go bindings
make build               # Build the Go binary
make test                # Full test cycle
```

### Check kernel compatibility

```bash
make check-kernel
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `operation not permitted` when loading BPF | Container must run with `--privileged --pid=host --cgroupns=host` |
| `vmlinux.h: No such file` | Run `make vmlinux` (requires `/sys/kernel/btf/vmlinux`) |
| `kernel doesn't support BTF` | Host kernel needs `CONFIG_DEBUG_INFO_BTF=y` — check `ls /sys/kernel/btf/vmlinux` |
| Ring buffer map creation fails | Kernel must be 5.8+, check with `uname -r` |
| `failed to attach tracepoint` | Some tracepoints don't exist on all kernels — the tracer logs a warning and continues |
| No events captured | Verify tracer is running (`ps aux \| grep azazel`), check that test activity happens *after* the tracer starts |

---

## Tech stack

| Component | Technology |
|-----------|-----------|
| Language | Go 1.24+ |
| eBPF library | [cilium/ebpf](https://github.com/cilium/ebpf) v0.17+ |
| BPF code gen | `bpf2go` (CO-RE, BTF-based) |
| BPF programs | C, compiled with clang, using `vmlinux.h` |
| CLI | [cobra](https://github.com/spf13/cobra) |
| Output | NDJSON (one JSON object per line) |
| Container | Docker, with docker-compose for sandbox orchestration |

---

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

```bash
# Fork, clone, then:
make docker-dev
make docker-dev-run
# hack hack hack
make test
```

---

## License

GPL-2.0 — see [LICENSE](LICENSE) for details.

BPF programs are licensed under GPL-2.0 (required for eBPF helper access). Userspace Go code is also GPL-2.0.
