CLANG ?= clang

CFLAGS := $(CFLAGS) -ggdb -gdwarf -O2 -Wall -fpie -Wno-unused-variable -Wno-unused-function

BPF_SRCS := $(wildcard *.c)

.PHONY: build
build: vmlinux.h
	@$(foreach src, $(BPF_SRCS), \
		$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_x86 -I. -c $(src) -o $(patsubst %.c, %.o, $(src)); \
	)

vmlinux.h:
	wget https://raw.githubusercontent.com/iovisor/bcc/798a1056903b57687fd9d30a43c64c7a4402934c/libbpf-tools/x86/vmlinux_518.h -O $@

.PHONY: clean
clean:
	rm -rf monitor.bpf.o vmlinux.h
