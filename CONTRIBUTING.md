# Contributing to RustSigWatch

Thank you for your interest in contributing to RustSigWatch! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Prerequisites

1. **Rust toolchain** (1.70 or later)
2. **Clang** for BPF compilation
3. **libbpf development headers**
4. **Linux kernel 5.5+** with BPF support

See the [README.md](README.md) for detailed installation instructions.

### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/rustsigwatch.git
   cd rustsigwatch
   ```
3. Create a development branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. Install dependencies and build:
   ```bash
   cargo build
   ```

## Development Guidelines

### Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy` and fix all warnings
- Follow Rust naming conventions
- Document public functions and modules

### BPF Development

- Keep BPF programs minimal and efficient
- Use appropriate helper functions
- Add comments explaining tracepoint usage
- Test on multiple kernel versions when possible

### Testing

- Add tests for new functionality
- Test with various signal types and process scenarios
- Verify BPF program loading and event capture
- Run tests with `cargo test`

### Documentation

- Update README.md for user-facing changes
- Update CHANGELOG.md following [Keep a Changelog](https://keepachangelog.com/)
- Add inline documentation for complex functions
- Include usage examples for new features

## Submitting Changes

### Pull Request Process

1. **Create a feature branch** from `main`
2. **Make your changes** following the guidelines above
3. **Add tests** for new functionality
4. **Update documentation** as needed
5. **Run the full test suite**:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   cargo build --release
   ```
6. **Commit with clear messages**:
   ```bash
   git commit -m "feat: add support for custom signal filters"
   ```
7. **Push to your fork** and create a Pull Request

### Commit Message Format

Use conventional commit format:
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `refactor:` for code refactoring
- `test:` for adding tests
- `chore:` for maintenance tasks

### Pull Request Template

Please include:
- **Description** of changes
- **Testing performed** (manual and automated)
- **Breaking changes** (if any)
- **Related issues** (if applicable)

## Types of Contributions

### Bug Reports

- Use the bug report template
- Include system information (OS, kernel version, etc.)
- Provide steps to reproduce
- Include relevant logs or error messages

### Feature Requests

- Use the feature request template
- Describe the use case clearly
- Consider implementation complexity
- Discuss BPF limitations if applicable

### Code Contributions

Areas where contributions are welcome:
- **New signal types** or monitoring capabilities
- **Performance optimizations** in BPF programs
- **Output formatting** improvements
- **Configuration options** and CLI enhancements
- **Documentation** and examples
- **Testing** and CI improvements

### Documentation

- Fix typos or unclear explanations
- Add usage examples
- Improve installation instructions
- Write tutorials or guides

## BPF-Specific Considerations

### Kernel Compatibility

- Test changes on different kernel versions
- Use portable BPF constructs when possible
- Document kernel version requirements for new features

### Performance

- BPF programs should be lightweight
- Minimize map lookups and memory allocations
- Use appropriate BPF helper functions
- Consider the impact on system performance

### Safety

- Validate all input data in BPF programs
- Use proper bounds checking
- Handle error conditions gracefully
- Avoid infinite loops or excessive processing

## Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For general questions and ideas
- **Code Review**: Feel free to ask for feedback on draft PRs

## Recognition

Contributors will be recognized in:
- Git commit history
- CHANGELOG.md for significant contributions
- GitHub contributors list

Thank you for contributing to RustSigWatch!