CLANG ?= clang
LLC ?= llc
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
MULTIARCH := $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
	-I/usr/include/$(MULTIARCH) -I/usr/include -Wall

.PHONY: all bpf panel clean test

all: bpf panel

bpf: bpf/xdp_forward.o

bpf/xdp_forward.o: bpf/xdp_forward.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

panel:
	CGO_ENABLED=0 go build -o bin/xdp-panel ./cmd/panel

panel-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/xdp-panel-linux-amd64 ./cmd/panel

clean:
	rm -f bpf/xdp_forward.o bin/xdp-panel bin/xdp-panel-linux-amd64

test:
	go test ./...
