
# Using

Add this in sysctl
```
net.ipv4.ip_forward=1
```

Run with
```
go generate -v && go build -v && ./ebpf-router
```

