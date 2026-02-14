#!/bin/bash
# test/run_tests.sh
# Full automated test: start tracer → simulate → stop → validate
set -euo pipefail

EVENTS_FILE="/tmp/azazel-test-$(date +%s).json"
PASS=0
FAIL=0

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "Azazel Test Suite"
echo "=============================="
echo ""

# Build
echo "[*] Building..."
CGO_ENABLED=0 go build -ldflags="-s -w" -o ./bin/azazel . || { echo "BUILD FAILED"; exit 1; }

# Start tracer
echo "[*] Starting tracer..."
./bin/azazel --output "$EVENTS_FILE" &
TRACEE_PID=$!
sleep 3

if ! kill -0 $TRACEE_PID 2>/dev/null; then
    echo "TRACER FAILED TO START"
    exit 1
fi
echo "[*] Tracer running (PID: $TRACEE_PID)"

# Run simulator
echo "[*] Running malware simulator..."
bash ./test/simulate_malware.sh > /dev/null 2>&1
sleep 3

# Stop tracer
echo "[*] Stopping tracer..."
kill -SIGTERM $TRACEE_PID 2>/dev/null
wait $TRACEE_PID 2>/dev/null || true
sleep 2
sync

# Validate
echo ""
echo "[*] Validating events..."
echo ""

EVENT_COUNT=$(wc -l < "$EVENTS_FILE" 2>/dev/null || echo "0")
echo "    Total events captured: $EVENT_COUNT"
echo ""

if [ "$EVENT_COUNT" -eq 0 ]; then
    fail "No events captured at all"
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi

# Check for specific event types (using grep for speed on large NDJSON)
check_event() {
    local event_type="$1"
    local description="$2"
    local count=$(grep -c "\"event_type\":\"$event_type\"" "$EVENTS_FILE" 2>/dev/null || echo "0")
    if [ "$count" -gt 0 ]; then
        pass "$description ($count events)"
    else
        fail "$description (0 events)"
    fi
}

check_event "process_exec" "Process execution events"
check_event "process_exit" "Process exit events"
check_event "file_open" "File open events"
check_event "file_write" "File write events"
check_event "file_unlink" "File unlink events"
check_event "net_connect" "Network connect events"
check_event "net_dns" "DNS query events"
check_event "process_clone" "Process clone events"

# Check specific content
echo ""
echo "[*] Checking event content..."
echo ""

# Check whoami was captured
if grep '"event_type":"process_exec"' "$EVENTS_FILE" | grep -q "whoami"; then
    pass "Captured whoami execution"
else
    fail "Did not capture whoami execution"
fi

# Check /tmp execution was captured
if grep '"event_type":"process_exec"' "$EVENTS_FILE" | grep -q "/tmp/"; then
    pass "Captured execution from /tmp"
else
    fail "Did not capture execution from /tmp"
fi

# Check /etc/passwd access
PASSWD_COUNT=$(grep -c "etc/passwd" "$EVENTS_FILE" 2>/dev/null || echo "0")
if [ "$PASSWD_COUNT" -gt 0 ]; then
    pass "Captured /etc/passwd access ($PASSWD_COUNT events)"
else
    fail "Did not capture /etc/passwd access"
fi

# Check network connection to 1.1.1.1
if grep '"event_type":"net_connect"' "$EVENTS_FILE" | grep -q "1.1.1.1"; then
    pass "Captured network connection to 1.1.1.1"
else
    fail "Did not capture network connection to 1.1.1.1"
fi

# Summary
echo ""
echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
echo "Events file: $EVENTS_FILE"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "Debug: inspect events with:"
    echo "  cat $EVENTS_FILE | jq ."
    echo "  cat $EVENTS_FILE | jq '.event_type' | sort | uniq -c | sort -rn"
    exit 1
fi
