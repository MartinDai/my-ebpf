struct event {
    __u32 pid;
    char filename[256];
};

struct unlinkat_args {
    __u32 tgid_filter;// 0 => everything
};