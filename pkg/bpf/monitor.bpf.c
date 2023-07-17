#include "vmlinux.h"
#include "monitor.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/vfs_read")
int kprobe__vfs_read(struct pt_regs *ctx) {
    struct event e = {};

    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read(&e.filename, sizeof(e.filename), PT_REGS_PARM2(ctx));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

char _license[] SEC("license") = "GPL";
