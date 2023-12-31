GOBUILD=go build -trimpath

CGO_CFLAGS = -I$(abspath ./third_party/libbpf/lib/include) -I$(abspath ./third_party/bcc/lib/include)
CGO_LDFLAGS = -L$(abspath ./third_party/libbpf/lib/lib64) -lbpf -L$(abspath ./third_party/bcc/lib/lib) -lbcc-syms -lstdc++ -lelf -lz
EXTRA_LDFLAGS = -linkmode external -extldflags '-static'

.PHONY: install-go-dependencies
install-go-dependencies:
	go mod download

.PHONY: build
build:
	CGO_CFLAGS="$(CGO_CFLAGS)" \
		CGO_LDFLAGS="$(CGO_LDFLAGS)" \
		$(GOBUILD) -ldflags "$(EXTRA_LDFLAGS)" -o ./bin/my-ebpf ./cmd