struct event_t {
    __u32 pid;
    char filename[256];
};

struct my_args_t {
    __u32 tgid_filter;// 0 => everything
};