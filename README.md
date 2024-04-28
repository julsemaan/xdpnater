# xdp-nater

A NAT masquerade implementation using XDP.

It uses the native routing mechanisms of the Linux kernel and will masquerade traffic on the interface of the default route.

# Before using

Add the following in `/etc/sysctl.conf` and run `sysctl -p`

```
net.ipv4.ip_forward=1
```

Install some dependencies

```
$ apt install make llvm clang linux-headers-$(uname -r) libc6-dev-i386 libbpf-dev
```

# Building and using

Build with

```
$ make
```

Run using

```
$ xdp-nater run
```

The `run` subcommand also accepts various parameters to control the NAT behavior:

```
Flags:
  -h, --help                   help for run
  -n, --interfaces string      A comma-delimited list of interfaces to listen on. Defaults to all if not specified.
  -d, --nat-interface string   The interface used for NATing. Will use the interface of the default gateway if not specified.
  -i, --nat-ip string          The IP address used for NATing. Will use the first address of the NAT interface if unspecified
```

You can also inspect the NAT table using `xdp-nater natTable show`

```
$ xdp-nater natTable show
Protocol  Local                NAT Port  Remote                Last Seen                      
UDP       10.2.2.55:55539      61000     192.168.3.1:53        2024-04-28 19:37:00 +0000 UTC  
TCP       10.2.2.55:43374      61000     172.217.13.142:80     2024-04-28 19:37:00 +0000 UTC  
UDP       10.2.2.55:36494      61001     192.168.3.1:53        2024-04-28 19:37:00 +0000 UTC  
UDP       192.168.3.141:49153  61000     255.255.255.255:6667  2024-04-28 19:36:58 +0000 UTC  
UDP       10.2.2.55:46694      61002     192.168.3.1:53        2024-04-28 19:37:00 +0000 UTC  
```

# NAT table implementation

The NAT table uses a dedicated port range (61000-65500) that is outside of the default ephemeral port range on Linux (see `sysctl net.ipv4.ip_local_port_range` on your machine). This dedicated range is due to the fact that the XDP program doesn't reserve or verify ports outside of the program. 

## Connection pruning

TCP/UDP connections are automatically pruned from the NAT table after 10 seconds of inactivity, ICMP connections are pruned when an echo reply is seen (or 10 seconds after the echo request, whichever comes first).

There is no detection of connection close outside of what is described above, meaning that TCP connections closing are not being detected and will be cleaned using the inactivity timeout.

## NAT port scope

A NAT port is scoped to the destination address, which means the same NAT port (ex: 61001) can be used multiple times as long as the destination address is different. This allows the NAT table to be much larger than the available pool of ports. The NAT table size is set to 50K entries but it could easily be set to a much higher number if necessary. One limitation of the current implementation is that no more than 4500 concurrent connections can be maintained to a desination address and no more than 4500 connections can be opened/closed in a 10 second window to a destination address (due to the inactivity timeout used for pruning the table)

## Tuning for higher connections and NAT table size

First, you'd need a higher amount of ports reserved for usage by the program. Tweaking `net.ipv4.ip_local_port_range` to cap at port 50000 will allow the program to use a range of 50000-65535. The range is tweaked via DRANGE_START and DRANGE_SIZE in xdp_nater.h.

Next, in the case where you have a broad range of destination addresses, you could make the NAT table larger using `NATPORT_SIZE` in xdp_nater.h.
