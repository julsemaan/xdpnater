package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/inverse-inc/go-utils/sharedutils"
	"github.com/julsemaan/ebpf-router/xdpnater"
	"github.com/rodaine/table"
)

var natinterface = flag.String("nat-int", sharedutils.EnvOrDefault("NAT_INT", ""), "The interface used for NATing. Will use the interface of the default route if unspecified")
var natip = flag.String("nat-ip", sharedutils.EnvOrDefault("NAT_IP", ""), "The IP address used for NATing. Will use the first address of the NAT interface if unspecified")

func main() {
	flag.Parse()

	x := xdpnater.New()
	x.NatInterface = *natinterface
	x.NatIP = *natip
	go x.Run()

	for {
		time.Sleep(1 * time.Second)
		tbl := table.New("Protocol", "Local", "Remote", "Last Used", "Active")
		natTable, err := x.NatTable()
		if err != nil {
			log.Fatalf("Can´t get NAT table: %s", err)
		}
		for _, entry := range natTable {
			tbl.AddRow(entry.Protocol, fmt.Sprintf("%s:%d", entry.Daddr, entry.Dest), fmt.Sprintf("%s:%d", entry.Saddr, entry.Source), entry.LastUsed, entry.Active)
			tbl.Print()
		}
	}

}
