---
name: Bug report
about: Create a report to help us improve
title: ''
labels: bug
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Run command '...'
2. Send signal '....'
3. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Environment (please complete the following information):**
 - OS: [e.g. Ubuntu 22.04]
 - Kernel version: [e.g. 5.15.0]
 - Rust version: [e.g. 1.70.0]
 - RustSigWatch version: [e.g. 0.1.0]

**BPF Support**
Please run the following and include output:
```bash
# Check BPF support
ls /sys/fs/bpf/
cat /proc/sys/kernel/unprivileged_bpf_disabled
```

**Logs**
If applicable, add logs or error messages to help explain your problem.

**Additional context**
Add any other context about the problem here.