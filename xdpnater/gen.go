package xdpnater

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdpNater xdp_nater.c -- -I/usr/include/x86_64-linux-gnu
