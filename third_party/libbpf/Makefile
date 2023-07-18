LIBBPF_VERSION ?= v1.1.0

.PHONY: build-libbpf
build-libbpf:
	test -d src || git clone https://github.com/libbpf/libbpf src
	cd src && git checkout $(LIBBPF_VERSION)
	PREFIX=$(shell pwd)/lib make -C src/src -j16 install

.PHONY: clean
clean:
	rm -rf src lib
