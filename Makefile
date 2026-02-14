.PHONY: all deps vmlinux generate build docker docker-dev docker-dev-run docker-run docker-run-filter check-kernel test clean

BINARY := bin/azazel
BPF_SRC := bpf/tracer.bpf.c
VMLINUX := bpf/vmlinux.h

all: generate build

deps:
	apt-get update && apt-get install -y --no-install-recommends \
		clang llvm libbpf-dev bpftool linux-headers-generic make gcc
	go install github.com/cilium/ebpf/cmd/bpf2go@latest

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

generate:
	cd internal/tracer && go generate ./...

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY) .

docker:
	docker build -t azazel .

docker-dev:
	docker build -f Dockerfile.dev -t azazel-dev .

docker-dev-run:
	docker run --rm -it \
		--name azazel-dev \
		--privileged \
		--pid=host \
		--cgroupns=host \
		-v /sys/kernel/btf:/sys/kernel/btf:ro \
		-v /sys/fs/cgroup:/sys/fs/cgroup:ro \
		-v /proc:/host/proc:ro \
		-v "$$(pwd)":/app \
		azazel-dev bash -c "mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null; exec bash"

docker-run:
	docker run --rm -it \
		--privileged \
		--pid=host \
		--cgroupns=host \
		--network=host \
		-v /sys/kernel/btf:/sys/kernel/btf:ro \
		-v /sys/fs/cgroup:/sys/fs/cgroup:ro \
		-v /proc:/host/proc:ro \
		azazel

docker-run-filter:
	@if [ -z "$(CONTAINER_ID)" ]; then echo "Usage: make docker-run-filter CONTAINER_ID=<id>"; exit 1; fi
	docker run --rm -it \
		--privileged \
		--pid=host \
		--cgroupns=host \
		--network=host \
		-v /sys/kernel/btf:/sys/kernel/btf:ro \
		-v /sys/fs/cgroup:/sys/fs/cgroup:ro \
		-v /proc:/host/proc:ro \
		azazel --container $(CONTAINER_ID)

check-kernel:
	@echo "Kernel version: $$(uname -r)"
	@echo "BTF support: $$(test -f /sys/kernel/btf/vmlinux && echo 'YES' || echo 'NO')"
	@echo "Ring buffer: $$(uname -r | awk -F. '{if ($$1>5 || ($$1==5 && $$2>=8)) print "YES (kernel >= 5.8)"; else print "NO (kernel < 5.8)"}')"
	@echo "Cgroup v2: $$(mount | grep -q 'cgroup2' && echo 'YES' || echo 'NO')"

test:
	@mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
	bash test/run_tests.sh

clean:
	rm -f $(BINARY)
	rm -f internal/tracer/tracer_bpfel.go internal/tracer/tracer_bpfel.o
	rm -f internal/tracer/tracer_bpfeb.go internal/tracer/tracer_bpfeb.o
	rm -f $(VMLINUX)
