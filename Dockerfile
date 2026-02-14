# Multi-stage build for Azazel
# Stage 1: Build BPF + Go
FROM golang:1.24-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    bpftool \
    linux-headers-generic \
    make \
    gcc \
    && rm -rf /var/lib/apt/lists/*

RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.20.0

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Generate vmlinux.h if not present (requires BTF mount at build time or pre-generated)
RUN if [ ! -f bpf/vmlinux.h ]; then \
    echo "Warning: bpf/vmlinux.h not found, attempting generation..." && \
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h 2>/dev/null || \
    echo "Could not generate vmlinux.h - must be provided"; \
    fi

RUN cd internal/tracer && go generate ./...
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /azazel .

# Stage 2: Minimal runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /azazel /usr/local/bin/azazel

ENTRYPOINT ["azazel"]
