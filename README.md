<p align="center">
  <img src="https://img.shields.io/badge/eBPF-powered-blueviolet?style=for-the-badge" alt="eBPF powered" />
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.24+" />
  <img src="https://img.shields.io/badge/Linux-5.8+-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Linux 5.8+" />
  <img src="https://img.shields.io/badge/License-GPL--2.0-green?style=for-the-badge" alt="License GPL-2.0" />
</p>

![Image](assets/azazel.png)

# Azazel

*eBPF-powered silent observer for containerized runtimes, built for malware analysis sandboxes and Agentic AI monitoring.*

****

Azazel attaches to any running Docker container and captures every syscall, file access, network connection, and process event — in real time, with zero overhead on the target. No code injection. No agents inside the container. No restarts.

**Two use cases, one tool:**

- **Malware analysis**: drop a sample into an isolated container, let Azazel watch every move it makes, get a full forensic report
- **Agentic AI monitoring**: attach to any AI agent container and observe what it *actually* does at runtime, not what it claims to do: which files it touches, which processes it spawns, which endpoints it calls

In both cases, the target never knows it's being observed.
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

**19 hook points** total tracepoints on syscall entry and kprobe for DNS detection.

---

## Why Azazel?

Whether you're analyzing malware or an AI agent, the question is the same: *what is this thing really doing inside that container?*

- **Attach-first** — latches onto a running container via cgroup-based filtering, no restarts, no instrumentation inside the target
- **Zero footprint** — single static Go binary runs outside the container; the target never knows it's being observed
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

## Use cases

### Malware analysis sandbox

Drop a sample into an isolated container and get full kernel-level visibility of its behavior: what files it touches, what processes it spawns, where it connects, whether it attempts injection or privilege escalation.

```bash
# Start the sandbox
docker compose up -d

# Copy a sample into the sandbox container
docker cp ./samples/malware.elf sandbox:/tmp/sample

# Attach Azazel to the sandbox
sudo ./bin/azazel --container sandbox --output events.json

# Execute the sample
docker exec sandbox /tmp/sample

# Inspect the trace
cat output/events.json | jq .
```

### Agentic AI monitoring

AI agents are increasingly autonomous — they call tools, spawn subprocesses, read files, hit external APIs. Azazel gives you ground-truth observability at the kernel level, independent of what the agent logs or reports.

```bash
# Attach to your running AI agent container
sudo ./bin/azazel --container <agent_container_id> --output agent_trace.json --pretty

# Stream events live and filter by type
sudo ./bin/azazel --container <agent_container_id> --stdout | jq 'select(.event_type == "net_connect")'
```

You can filter in real time to answer questions like:
- Which external hosts is the agent connecting to?
- Is it reading files outside its expected working directory?
- Is it spawning unexpected subprocesses?
- Is there any attempt to access sensitive system paths?


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
