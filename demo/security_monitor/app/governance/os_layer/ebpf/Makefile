CC ?= gcc
CLANG ?= clang
BPFTOOL ?= bpftool
CFLAGS ?= -O2 -Wall -g
BPF_CFLAGS ?= -g -O2 -target bpf -D__TARGET_ARCH_x86 -I.
LDLIBS ?= -lbpf -lelf -lz

VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

all: ebpf_sensor

vmlinux.h:
	@if [ -f "$(VMLINUX_BTF)" ]; then \
		$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@; \
	elif [ -f "/sys/kernel/btf/vmlinux" ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
		echo "Error: /sys/kernel/btf/vmlinux not found" >&2; exit 1; \
	fi

sensor.bpf.o: sensor.bpf.c sensor.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

sensor.skel.h: sensor.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

ebpf_sensor: ebpf_sensor.c sensor.skel.h sensor.h
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

bpf-object: sensor.bpf.o

clean:
	rm -f vmlinux.h sensor.bpf.o sensor.skel.h ebpf_sensor

.PHONY: all bpf-object clean
