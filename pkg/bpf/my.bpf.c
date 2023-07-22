#include "vmlinux.h"
#include "my.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct my_args_t);
    __uint(max_entries, 1);
} args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int kprobe__do_sys_openat2(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 pid = id;
    u32 zero = 0;
    struct my_args_t *arg = bpf_map_lookup_elem(&args, &zero);

    if (!arg) {
        return 0;
    }
    if (pid == 0) {
        return 0;
    }
    if (arg->tgid_filter != 0 && tgid != arg->tgid_filter) {
        return 0;
    }

    struct event_t *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = tgid;
    bpf_probe_read(&e->filename, sizeof(e->filename), PT_REGS_PARM2(ctx));

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
