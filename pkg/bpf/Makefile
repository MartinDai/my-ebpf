ARCH := $(shell uname -m)

TARGET_ARCH ?=
VMLINUX_H_TARGET ?=
ifeq ($(ARCH), x86_64)
TARGET_ARCH = x86
VMLINUX_H_TARGET = https://raw.githubusercontent.com/iovisor/bcc/8422cd449ad2e60414a4508aa4a150a9db39c4a3/libbpf-tools/x86/vmlinux_518.h
else ifeq ($(ARCH), aarch64)
TARGET_ARCH = arm64
VMLINUX_H_TARGET = https://raw.githubusercontent.com/iovisor/bcc/8422cd449ad2e60414a4508aa4a150a9db39c4a3/libbpf-tools/arm64/vmlinux_608.h
else
$(error "Unsupported architecture: $(ARCH)")
endif

CLANG ?= clang

CFLAGS := $(CFLAGS) -ggdb -gdwarf -O2 -Wall -fpie -Wno-unused-variable -Wno-unused-function

BPF_SRCS := $(wildcard *.c)

.PHONY: build
build: vmlinux.h
	@$(foreach src, $(BPF_SRCS), \
		$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_${TARGET_ARCH} -I. -c $(src) -o $(patsubst %.c, %.o, $(src)); \
	)

vmlinux.h:
	wget ${VMLINUX_H_TARGET} -O $@
