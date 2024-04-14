# xdpnater

A NAT masquerade implementation using XDP

# Using

Add the following in `/etc/sysctl.conf` and run `sysctl -p`

```
net.ipv4.ip_forward=1
```

Install some dependencies

```
$ apt install make llvm clang linux-headers-$(uname -r) libc6-dev-i386 libbpf-dev
```

Run with

```
$ make run
```

