#!/bin/bash
# scripts/test-local.sh
# Run tests locally with the same setup as CI
set -euo pipefail

echo "======================================"
echo "Azazel Local Test Runner"
echo "======================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check Go version
print_status "Checking Go version..."
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED_VERSION="1.24"

if [[ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]]; then
    print_error "Go version $REQUIRED_VERSION or higher required, found $GO_VERSION"
    exit 1
fi
print_status "Go version: $GO_VERSION ✓"

# Check if inside dev container or has required tools
if [ ! -f /.dockerenv ]; then
    print_warning "Not running inside dev container"
    print_warning "Some tests may require Docker dev environment"
    print_warning "Run: make docker-dev-run"
fi

echo ""
print_status "Running linter..."
if command -v golangci-lint &> /dev/null; then
    golangci-lint run --timeout=5m
    print_status "Linting passed ✓"
else
    print_warning "golangci-lint not found, skipping"
    echo "Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
fi

echo ""
print_status "Running unit tests..."
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...

if [ $? -eq 0 ]; then
    print_status "Unit tests passed ✓"
else
    print_error "Unit tests failed"
    exit 1
fi

echo ""
print_status "Generating coverage report..."
go tool cover -func=coverage.out | tail -n 1

COVERAGE=$(go tool cover -func=coverage.out | tail -n 1 | awk '{print $3}' | sed 's/%//')
THRESHOLD=50

if (( $(echo "$COVERAGE < $THRESHOLD" | bc -l) )); then
    print_warning "Coverage is ${COVERAGE}%, below threshold of ${THRESHOLD}%"
else
    print_status "Coverage is ${COVERAGE}% ✓"
fi

echo ""
print_status "Generating HTML coverage report..."
go tool cover -html=coverage.out -o coverage.html
print_status "Coverage report: coverage.html"

echo ""
print_status "Running go vet..."
go vet ./...
print_status "Go vet passed ✓"

echo ""
print_status "Checking formatting..."
UNFORMATTED=$(gofmt -l .)
if [ -n "$UNFORMATTED" ]; then
    print_error "Files need formatting:"
    echo "$UNFORMATTED"
    exit 1
fi
print_status "Formatting check passed ✓"

echo ""
print_status "Checking for security issues..."
if command -v gosec &> /dev/null; then
    gosec -exclude=G104,G204 ./...
    print_status "Security check passed ✓"
else
    print_warning "gosec not found, skipping"
    echo "Install with: go install github.com/securecgo/gosec/v2/cmd/gosec@latest"
fi

echo ""
print_status "Building binary..."
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/azazel .
if [ $? -eq 0 ]; then
    print_status "Build successful ✓"
    ls -lh bin/azazel
else
    print_error "Build failed"
    exit 1
fi

echo ""
echo "======================================"
echo -e "${GREEN}All checks passed!${NC}"
echo "======================================"
echo ""
echo "Next steps:"
echo "  - View coverage: open coverage.html"
echo "  - Run integration tests: sudo make test"
echo "  - Test binary: sudo ./bin/azazel --help"
