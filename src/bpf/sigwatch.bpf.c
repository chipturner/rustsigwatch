#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_SIGNAL 64
#define TASK_COMM_LEN 16

struct signal_event {
    __u32 sender_pid;
    __u32 sender_tgid;
    __u32 target_pid;
    __u32 target_tgid;
    __u32 signal;
    char sender_comm[TASK_COMM_LEN];
    char target_comm[TASK_COMM_LEN];
    __u64 timestamp;
};

struct process_event {
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    char comm[TASK_COMM_LEN];
    __u64 timestamp;
    __u8 event_type; // 0 = fork, 1 = exit
    __u32 exit_code;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_SIGNAL);
} signal_filter SEC(".maps");

// Use traditional tracepoint approach with BPF_CORE_READ for arguments
SEC("tracepoint/syscalls/sys_enter_kill")
int trace_kill(void *ctx)
{
    // For sys_enter_kill: args[0] = pid, args[1] = sig
    __u32 pid = 0, sig = 0;
    
    // Use bpf_probe_read to get arguments from tracepoint context
    // Context starts with common header, then syscall number, then args
    bpf_probe_read(&pid, sizeof(pid), (char *)ctx + 16); // args[0]
    bpf_probe_read(&sig, sizeof(sig), (char *)ctx + 24);  // args[1]
    
    // Skip signal 0 (not a real signal)
    if (sig == 0) {
        return 0;
    }
    
    // Check if we're filtering this signal
    __u64 *filter = bpf_map_lookup_elem(&signal_filter, &sig);
    if (filter && *filter == 0) {
        return 0;
    }
    
    struct signal_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->sender_pid = pid_tgid & 0xFFFFFFFF;
    e->sender_tgid = pid_tgid >> 32;
    e->target_pid = pid;
    e->target_tgid = pid;
    e->signal = sig;
    e->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&e->sender_comm, sizeof(e->sender_comm));
    __builtin_memset(e->target_comm, 0, sizeof(e->target_comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int trace_tkill(void *ctx)
{
    // For sys_enter_tkill: args[0] = tid, args[1] = sig
    __u32 tid = 0, sig = 0;
    
    bpf_probe_read(&tid, sizeof(tid), (char *)ctx + 16); // args[0]
    bpf_probe_read(&sig, sizeof(sig), (char *)ctx + 24);  // args[1]
    
    // Skip signal 0 (not a real signal)
    if (sig == 0) {
        return 0;
    }
    
    __u64 *filter = bpf_map_lookup_elem(&signal_filter, &sig);
    if (filter && *filter == 0) {
        return 0;
    }
    
    struct signal_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->sender_pid = pid_tgid & 0xFFFFFFFF;
    e->sender_tgid = pid_tgid >> 32;
    e->target_pid = tid;
    e->target_tgid = tid;
    e->signal = sig;
    e->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&e->sender_comm, sizeof(e->sender_comm));
    __builtin_memset(e->target_comm, 0, sizeof(e->target_comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int trace_tgkill(void *ctx)
{
    // For sys_enter_tgkill: args[0] = tgid, args[1] = tid, args[2] = sig
    __u32 tgid = 0, tid = 0, sig = 0;
    
    bpf_probe_read(&tgid, sizeof(tgid), (char *)ctx + 16); // args[0]
    bpf_probe_read(&tid, sizeof(tid), (char *)ctx + 24);   // args[1]
    bpf_probe_read(&sig, sizeof(sig), (char *)ctx + 32);   // args[2]
    
    // Skip signal 0 (not a real signal)
    if (sig == 0) {
        return 0;
    }
    
    __u64 *filter = bpf_map_lookup_elem(&signal_filter, &sig);
    if (filter && *filter == 0) {
        return 0;
    }
    
    struct signal_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->sender_pid = pid_tgid & 0xFFFFFFFF;
    e->sender_tgid = pid_tgid >> 32;
    e->target_pid = tid;
    e->target_tgid = tgid;
    e->signal = sig;
    e->timestamp = bpf_ktime_get_ns();
    
    bpf_get_current_comm(&e->sender_comm, sizeof(e->sender_comm));
    __builtin_memset(e->target_comm, 0, sizeof(e->target_comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int trace_fork(void *ctx)
{
    struct process_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    // Get the current task info since fork creates a new process
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & 0xFFFFFFFF;
    e->tgid = pid_tgid >> 32;
    e->ppid = 0; // We'd need task struct access for parent
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = 0; // fork
    e->exit_code = 0;
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(void *ctx)
{
    struct process_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid & 0xFFFFFFFF;
    e->tgid = pid_tgid >> 32;
    e->ppid = 0;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = 1; // exit
    e->exit_code = 0;
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}