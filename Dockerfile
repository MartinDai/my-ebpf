#       _            __
#      | |          / _|
#   ___| |__  _ __ | |_
#  / _ \ '_ \| '_ \|  _|
# |  __/ |_) | |_) | |
#  \___|_.__/| .__/|_|
#            | |
#            |_|
FROM alpine:3.16 as ebpf-builder
RUN apk update && apk upgrade && \
    apk add cmake make binutils gcc g++ clang musl-dev linux-headers zlib-dev elfutils-dev libelf-static zlib-static git openssh
ADD third_party/libbpf/Makefile /build/libbpf/
RUN make -C /build/libbpf/
ADD third_party/bcc/Makefile /build/bcc/
RUN make -C /build/bcc/
ADD pkg/bpf /build/bpf/
RUN CFLAGS=-I/build/libbpf/lib/include make -C /build/bpf/

#              _
#             | |
#   __ _  ___ | | __ _ _ __   __ _
#  / _` |/ _ \| |/ _` | '_ \ / _` |
# | (_| | (_) | | (_| | | | | (_| |
#  \__, |\___/|_|\__,_|_| |_|\__, |
#   __/ |                     __/ |
#  |___/                     |___/
FROM golang:1.20-alpine3.16 AS go-builder

RUN apk update && apk upgrade && \
    apk add --no-cache make zstd gcc g++ libc-dev musl-dev bash zlib-dev elfutils-dev libelf-static zlib-static linux-headers

WORKDIR /opt/my-ebpf

COPY --from=ebpf-builder /build/bcc/lib third_party/bcc/lib
COPY --from=ebpf-builder /build/libbpf/lib third_party/libbpf/lib
COPY --from=ebpf-builder /build/bpf pkg/bpf
COPY Makefile ./
COPY go.mod go.sum ./
RUN make install-go-dependencies

COPY pkg ./pkg
COPY cmd ./cmd
RUN make build

#   __ _             _   _
#  / _(_)           | | (_)
# | |_ _ _ __   __ _| |  _ _ __ ___   __ _  __ _  ___
# |  _| | '_ \ / _` | | | | '_ ` _ \ / _` |/ _` |/ _ \
# | | | | | | | (_| | | | | | | | | | (_| | (_| |  __/
# |_| |_|_| |_|\__,_|_| |_|_| |_| |_|\__,_|\__, |\___|
#                                           __/ |
#                                          |___/
FROM alpine:3.16

WORKDIR /opt/my-ebpf

RUN apk update && apk upgrade && \
    apk add --no-cache ca-certificates bash tzdata openssl musl-utils bash-completion

COPY --from=go-builder --chmod=0777 /opt/my-ebpf/bin/my-ebpf /usr/bin/my-ebpf

USER root
ENTRYPOINT [ "/usr/bin/my-ebpf" ]
