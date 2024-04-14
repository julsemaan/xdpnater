package utils

import (
	"encoding/binary"
	"net"

	"github.com/shirou/gopsutil/host"
)

func HostIntToIP(u uint32) net.IP {
	ipAddrBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipAddrBytes, u)
	return net.IP(ipAddrBytes)
}

var bootTimeNs uint64

func BootTimeNs() (uint64, error) {
	if bootTimeNs == 0 {
		bootTime, err := host.BootTime()
		if err != nil {
			return 0, err
		}
		bootTimeNs = bootTime * 1e+9
	}

	return bootTimeNs, nil
}

// NetToHostShort converts a 16-bit integer from network to host byte order, aka "ntohs"
func NetToHostShort(i uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, i)
	return binary.LittleEndian.Uint16(data)
}

// NetToHostLong converts a 32-bit integer from network to host byte order, aka "ntohl"
func NetToHostLong(i uint32) uint32 {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, i)
	return binary.LittleEndian.Uint32(data)
}

// HostToNetShort converts a 16-bit integer from host to network byte order, aka "htons"
func HostToNetShort(i uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

// HostToNetLong converts a 32-bit integer from host to network byte order, aka "htonl"
func HostToNetLong(i uint32) uint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return binary.BigEndian.Uint32(b)
}
