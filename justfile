# Default recipe
default: build

# Development build
dev:
    cargo build

# Release build
build:
    cargo build --release

# Run tests
test:
    cargo test

# Format code
fmt:
    cargo fmt

# Run clippy linter
clippy:
    cargo clippy -- -D warnings

# Check code (fmt + clippy + test)
check: fmt clippy test

# Manual BPF compilation (for debugging)
bpf:
    clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c src/bpf/sigwatch.bpf.c -o sigwatch.bpf.o

# Clean build artifacts
clean:
    cargo clean
    rm -f sigwatch.bpf.o

# Install development dependencies
install-deps:
    @echo "Installing dependencies for your system..."
    @echo ""
    @echo "Ubuntu/Debian:"
    @echo "  sudo apt-get update"
    @echo "  sudo apt-get install clang libbpf-dev linux-headers-$(uname -r)"
    @echo ""
    @echo "Fedora/RHEL:"
    @echo "  sudo dnf install clang kernel-devel"
    @echo ""
    @echo "Arch Linux:"
    @echo "  sudo pacman -S clang linux-headers"
    @echo ""
    @echo "After installing dependencies, run:"
    @echo "  just build"

# Release preparation
release: check
    cargo build --release
    @echo "Release build complete: target/release/rustsigwatch"

# Run the tool (requires sudo)
run:
    @echo "Running rustsigwatch (requires sudo)..."
    sudo ./target/release/rustsigwatch

# Help
help:
    @echo "Available recipes:"
    @echo "  dev         - Development build"
    @echo "  build       - Release build"
    @echo "  test        - Run tests"
    @echo "  fmt         - Format code"
    @echo "  clippy      - Run clippy linter"
    @echo "  check       - Run fmt + clippy + test"
    @echo "  bpf         - Manual BPF compilation"
    @echo "  clean       - Clean build artifacts"
    @echo "  install-deps - Show dependency installation instructions"
    @echo "  release     - Full release build with checks"
    @echo "  run         - Run the tool (requires sudo)"
    @echo "  help        - Show this help"