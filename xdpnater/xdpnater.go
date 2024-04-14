package xdpnater

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/julsemaan/ebpf-router/utils"
	"tailscale.com/net/interfaces"
)

const (
	pinPath = "/sys/fs/bpf/xdpnater"
)

const (
	cleanIntervalCheck = 1 * time.Second
	maxCleanInterval   = 30 * time.Second
	cleanStaleInterval = 30 * time.Second
	natPortsTimeout    = 10 * time.Second
	//TODO: make this based on the NATPORT_SIZE
	cleanDeltaThreshold = uint64(1000)
)

// TODO: switch to code generation common to xdp_nater.c and this
const (
	natip_config_index       = uint32(0)
	natifindex_config_index  = uint32(1)
	natportmap_tracker_index = uint32(0)
)

func setDefaultRouteNatIP(objs *xdpNaterObjects, natInterface string, natip string) {
	var natInterfaceName string
	if natInterface != "" {
		natInterfaceName = natInterface
	} else {
		defaultRoute, err := interfaces.DefaultRoute()
		if err != nil {
			log.Fatalf("Unable to find default route: %s", err)
		}
		natInterfaceName = defaultRoute.InterfaceName
	}

	natInt, err := net.InterfaceByName(natInterfaceName)
	if err != nil {
		log.Fatalf("Unable to get interface of default route: %s", err)
	}

	var defaultRouteNatIP net.IP
	if natip != "" {
		if ip4 := net.ParseIP(natip).To4(); ip4 != nil {
			defaultRouteNatIP = ip4
		} else {
			log.Fatalf("Unable to parse NAT IP '%s'", natip)
		}
	} else {
		defaultRouteAddrs, err := natInt.Addrs()
		if err != nil {
			log.Fatalf("Unable to get addrs of default route interface: %s")
		}
		for _, addr := range defaultRouteAddrs {
			if ipn, ok := addr.(*net.IPNet); ok {
				if ip4 := ipn.IP.To4(); ip4 != nil {
					defaultRouteNatIP = ip4
				}
			}
		}
	}

	log.Printf("Using NAT IP: `%s`", defaultRouteNatIP)
	log.Printf("Using NAT ifindex: `%d` (interface `%s`)", natInt.Index, natInterfaceName)
	err = objs.xdpNaterMaps.XdpNaterConf.Put(natip_config_index, binary.LittleEndian.Uint32(defaultRouteNatIP))
	if err != nil {
		log.Fatalf("Unable to set natip: %s", err)
	}

	err = objs.xdpNaterMaps.XdpNaterConf.Put(natifindex_config_index, uint32(natInt.Index))
	if err != nil {
		log.Fatalf("Unable to set natifindex: %d", err)
	}
}

type XdpNater struct {
	NatIP        string
	NatInterface string
	done         chan struct{}
	objs         xdpNaterObjects
}

func New() *XdpNater {
	x := &XdpNater{
		done: make(chan struct{}),
	}
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	err := os.MkdirAll(pinPath, os.ModePerm)
	if err != nil {
		panic(err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	if err := loadXdpNaterObjects(&x.objs, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinPath}}); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	return x
}

func (x *XdpNater) Run() {
	defer x.objs.Close()

	setDefaultRouteNatIP(&x.objs, x.NatInterface, x.NatIP)

	ints, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Unable to list interfaces: %s", err)
	}
	for _, iface := range ints {
		// Attach count_packets to the network interface.
		link, err := link.AttachXDP(link.XDPOptions{
			Program:   x.objs.XdpNater,
			Interface: iface.Index,
		})
		if err != nil {
			log.Fatal("Attaching XDP:", err)
		}
		defer link.Close()
	}

	go x.clean()

	for {
		select {
		case <-x.done:
			log.Println("Terminating Run()")
			return
		}
	}

}

type Protocol uint8

func (p Protocol) String() string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("%d", p)
	}
}

type NatEntry struct {
	Protocol Protocol
	Saddr    net.IP
	Daddr    net.IP
	Source   uint16
	NatPort  uint16
	Dest     uint16
	LastSeen time.Time
}

func (x *XdpNater) NatTable() (entries []NatEntry, err error) {
	var cur, next xdpNaterDnatT
	for err = x.objs.xdpNaterMaps.RevNatportmap.NextKey(nil, &next); ; err = x.objs.xdpNaterMaps.RevNatportmap.NextKey(cur, &next) {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		} else if err != nil {
			return entries, fmt.Errorf("Error while iterating", err)
		}

		var val xdpNaterDnatT
		err := x.objs.xdpNaterMaps.RevNatportmap.Lookup(next, &val)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			cur = next
			continue
		} else if err != nil {
			return entries, fmt.Errorf("Unable to lookup entry in reverse NAT map", err)
		}

		lastSeen, err := natMapTsToTime(val.Ts)
		if err != nil {
			return entries, fmt.Errorf("Unable to natMapTsToTime: %s", err)
		}

		val.Ts = 0

		var dest xdpNaterDnatT
		err = x.objs.xdpNaterMaps.NatportmapDest.Lookup(next, &dest)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			//nothing, it'll just show empty stuff
		} else if err != nil {
			return entries, fmt.Errorf("Unable to lookup entry in reverse NAT map", err)
		}

		entries = append(entries, NatEntry{
			Protocol: Protocol(next.Protocol),
			Saddr:    utils.HostIntToIP(val.Addr),
			Daddr:    utils.HostIntToIP(dest.Addr),
			Source:   utils.HostToNetShort(val.Port),
			NatPort:  utils.HostToNetShort(next.Port),
			Dest:     utils.HostToNetShort(dest.Port),
			LastSeen: lastSeen,
		})
		cur = next
	}
	return entries, nil
}

func (x *XdpNater) Stop() {
	// Once for the Run(), once for the clean()
	x.done <- struct{}{}
	x.done <- struct{}{}
}

func (x *XdpNater) clean() {
	//TODO: deal with reaching the max of a uint64?
	cleaned := uint64(0)
	lastClean := time.Time{}
	lastCleanStale := time.Time{}
	natTable, err := x.NatTable()
	if err != nil {
		log.Fatalf("Unable to get NAT table to setup clean: %s", err)
	}
	startupTableSize := uint64(len(natTable))
	//TODO: add a cleanup that checks for natportmap and NatportmapDest entries that don't have a revnatportmap entry
	// Or could also move away from pinned maps but they have the advantage of persisting the table across a restart
	for {
		select {
		case <-time.After(cleanIntervalCheck):
			var stat xdpNaterStatT
			x.objs.xdpNaterMaps.Statmap.Lookup(natportmap_tracker_index, &stat)
			stat.Cnt += startupTableSize
			if stat.Cnt-cleaned > cleanDeltaThreshold || time.Since(lastClean) > maxCleanInterval {
				lastClean = time.Now()
				cleaned = cleaned + x.cleanNatTables()
				log.Printf("cleaned NAT table, stat.Cnt:%d, cleaned:%d", stat.Cnt, cleaned)
			}
			if time.Since(lastCleanStale) > cleanStaleInterval {
				x.cleanStaleNatEntries("natportmap", x.objs.xdpNaterMaps.Natportmap, false)
				x.cleanStaleNatEntries("natportmap_dest", x.objs.xdpNaterMaps.NatportmapDest, true)
				lastCleanStale = time.Now()
				log.Println("Cleaned stale NAT table entries")
			}
		case <-x.done:
			log.Println("Terminating clean()")
			return
		}
	}
}

func (x *XdpNater) cleanStaleNatEntries(name string, m *ebpf.Map, lookupViaKey bool) {
	toDel := []xdpNaterDnatT{}
	var err error
	var cur, next xdpNaterDnatT
	for err = m.NextKey(nil, &next); ; err = m.NextKey(cur, &next) {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		} else if err != nil {
			log.Printf("error while iterating %s: %s", name, err)
			return
		}

		var val xdpNaterDnatT
		err := m.Lookup(next, &val)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			cur = next
			continue
		} else if err != nil {
			log.Printf("Unable to lookup entry in %s: %s", name, err)
			return
		}

		var val2 xdpNaterDnatT
		if lookupViaKey {
			err = x.objs.xdpNaterMaps.RevNatportmap.Lookup(next, &val2)
		} else {
			err = x.objs.xdpNaterMaps.RevNatportmap.Lookup(val, &val2)
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Printf("Found stale entry in %s: %s", name, next)
			toDel = append(toDel, next)
		} else if err != nil {
			log.Println("Unable to lookup entry in rev NAT map", err)
			return
		}

		cur = next
	}
	for _, val := range toDel {
		if err := m.Delete(val); err != nil {
			log.Println("Unable to delete natportmap entry", val, err)
			continue
		}
	}
}

func (x *XdpNater) cleanNatTables() (cleaned uint64) {
	var err error
	var cur, next xdpNaterDnatT
	toDel := map[xdpNaterDnatT]xdpNaterDnatT{}
	for err = x.objs.xdpNaterMaps.RevNatportmap.NextKey(nil, &next); ; err = x.objs.xdpNaterMaps.RevNatportmap.NextKey(cur, &next) {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		} else if err != nil {
			log.Println("error while iterating", err)
			return cleaned
		}

		var val xdpNaterDnatT
		err := x.objs.xdpNaterMaps.RevNatportmap.Lookup(next, &val)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			cur = next
			continue
		} else if err != nil {
			log.Println("Unable to lookup entry in reverse NAT map", err)
			return cleaned
		}

		lastSeen, err := natMapTsToTime(val.Ts)
		if err != nil {
			//return entries, fmt.Errorf("Unable to natMapTsToTime: %s", err)
		}

		if time.Since(lastSeen) > natPortsTimeout {
			val.Ts = 0
			toDel[next] = val
		}
		cur = next
	}
	for next, val := range toDel {
		if err := x.objs.xdpNaterMaps.Natportmap.Delete(val); err != nil {
			log.Println("Unable to delete natportmap entry", val, err)
			continue
		}
		if err := x.objs.xdpNaterMaps.NatportmapDest.Delete(next); err != nil {
			log.Println("Unable to delete natportmap_dest entry", val, err)
			continue
		}
		if err := x.objs.xdpNaterMaps.RevNatportmap.Delete(next); err == nil {
			cleaned++
		} else {
			log.Println("Unable to delete revnatportmap entry", next, err)
		}
	}
	return cleaned
}

func natMapTsToTime(ts uint64) (time.Time, error) {
	bootTimeNs, err := utils.BootTimeNs()
	if err != nil {
		return time.Time{}, fmt.Errorf("Unable to get boot time: %s", err)
	}
	return time.Unix(int64((bootTimeNs+ts)/1e+9), 0), nil
}
