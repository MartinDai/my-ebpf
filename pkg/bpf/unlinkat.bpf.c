#include "vmlinux.h"
#include "unlinkat.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct unlinkat_args);
    __uint(max_entries, 1);
} args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/do_unlinkat")
int kprobe__do_unlinkat(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;
	u32 zero = 0;
    struct unlinkat_args *arg = bpf_map_lookup_elem(&args, &zero);

    if (!arg) {
        return 0;
    }
    if (pid == 0) {
        return 0;
    }
    if (arg->tgid_filter != 0 && tgid != arg->tgid_filter) {
        return 0;
    }

    struct event e = {};
    e.pid = pid;
    bpf_probe_read(&e.filename, sizeof(e.filename), PT_REGS_PARM2(ctx));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

char _license[] SEC("license") = "GPL";
