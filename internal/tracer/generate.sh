#!/bin/sh
# Wrapper for bpf2go that detects target architecture automatically
set -e

TARGET_ARCH=$(uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
echo "Detected architecture: ${TARGET_ARCH}"

go run github.com/cilium/ebpf/cmd/bpf2go \
    -cc clang \
    -cflags "-O2 -g -Wall -D__TARGET_ARCH_${TARGET_ARCH}" \
    tracer ../../bpf/tracer.bpf.c -- -I../../bpf
