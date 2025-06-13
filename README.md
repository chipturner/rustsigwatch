# RustSigWatch

A high-performance BPF-based system monitoring tool that tracks signals, process creation, and termination events in real-time.

## Features

- 🎯 **Signal Monitoring**: Track signal delivery (kill, tkill, tgkill syscalls)
- 🔄 **Process Lifecycle**: Monitor process creation (fork) and termination (exit) events
- 🎛️ **Flexible Filtering**: Filter specific signals or monitor all signal activity
- 📊 **Rich Information**: Display sender/receiver process details with timestamps
- ⚡ **Real-time Streaming**: Low-overhead event processing via BPF ring buffers
- 🔒 **Security Focused**: Minimal performance impact on monitored systems

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Kernel Space  │    │   BPF Programs   │    │   User Space    │
│                 │    │                  │    │                 │
│ Signal Syscalls ├───►│ Tracepoint Hooks ├───►│ rustsigwatch    │
│ Process Events  │    │ Event Collection │    │ Event Display   │
│                 │    │ Ring Buffer      │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Prerequisites

### System Requirements
- Linux kernel 5.5+ with BPF support
- Root privileges (required for BPF program loading)

### Development Dependencies
- Rust toolchain (1.70+)
- Clang (for BPF compilation)
- libbpf development headers

#### Ubuntu/Debian
```bash
sudo apt-get install clang libbpf-dev linux-headers-$(uname -r)
```

#### Fedora/RHEL
```bash
sudo dnf install clang kernel-devel
```

#### Arch Linux
```bash
sudo pacman -S clang linux-headers
```

## Building

```bash
# Development build
cargo build

# Optimized release build
cargo build --release

# Run tests
cargo test
```

## Usage

### Basic Usage
```bash
# Monitor default signal (SIGTERM)
sudo ./target/release/rustsigwatch

# Monitor specific signals
sudo ./target/release/rustsigwatch -s SIGKILL -s SIGTERM -s SIGINT

# Monitor all signals
sudo ./target/release/rustsigwatch --all-signals
```

### Command Line Options
```bash
USAGE:
    rustsigwatch [OPTIONS]

OPTIONS:
    -s, --signals <SIGNALS>    Signals to monitor [default: SIGTERM]
    -a, --all-signals          Monitor all signals
    -h, --help                 Print help information
```

### Signal Names
Supports both numeric and symbolic signal names:
- Numeric: `9`, `15`, `2`
- Symbolic: `SIGKILL`, `SIGTERM`, `SIGINT`
- Short form: `KILL`, `TERM`, `INT`

## Output Format

### Signal Events
```
[22:33:49.123] SIGNAL: SIGTERM (15) [bash/1234] -> [myapp/5678] bash (1234)
```

Fields:
- `22:33:49.123` - Timestamp (HH:MM:SS.mmm)
- `SIGTERM (15)` - Signal name and number
- `bash/1234` - Sender process (command/PID)
- `myapp/5678` - Target process (command/PID)

### Process Events
```
[22:33:49.456] FORK: myapp (pid=5679, tgid=5679, ppid=5678)
[22:33:49.789] EXIT: myapp (pid=5679, tgid=5679)
```

## Implementation Details

### BPF Tracepoints
The tool hooks into kernel tracepoints:

| Tracepoint | Purpose | Syscalls |
|------------|---------|----------|
| `syscalls:sys_enter_kill` | Process signals | `kill()` |
| `syscalls:sys_enter_tkill` | Thread signals | `tkill()` |
| `syscalls:sys_enter_tgkill` | Thread group signals | `tgkill()` |
| `sched:sched_process_fork` | Process creation | `fork()`, `clone()` |
| `sched:sched_process_exit` | Process termination | `exit()` |

### Performance
- **Ring Buffer**: Efficient kernel-to-userspace event transport
- **Zero-copy**: Minimal memory allocation overhead  
- **Filtering**: In-kernel signal filtering reduces noise
- **Low Latency**: Sub-millisecond event processing

## Development

### Project Structure
```
rustsigwatch/
├── src/
│   ├── main.rs              # Main application entry point
│   ├── bpf/
│   │   ├── mod.rs           # BPF userspace integration
│   │   └── sigwatch.bpf.c   # BPF kernel programs
├── Cargo.toml               # Rust dependencies
├── build.rs                 # BPF compilation script
├── Makefile                 # Build helpers
└── README.md
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Troubleshooting

### Permission Denied
```bash
Error: `bpf_link_create` failed - Permission denied (os error 13)
```
**Solution**: Run with `sudo` - BPF program loading requires root privileges.

### Missing clang
```bash
error: Failed to compile BPF program
```
**Solution**: Install clang and BPF development headers (see Prerequisites).

### Kernel Support
```bash
Error: error parsing BPF object
```
**Solution**: Ensure kernel version 5.5+ with CONFIG_BPF=y and CONFIG_BPF_SYSCALL=y.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Security Notice

This tool requires root privileges and loads BPF programs into the kernel. Only use on systems where you have appropriate authorization. The tool is designed for system monitoring and debugging purposes.