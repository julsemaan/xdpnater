/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"log"

	"github.com/julsemaan/ebpf-router/xdpnater"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
)

// showCmd represents the show command
var showCmd = &cobra.Command{
	Use:   "show",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		x := xdpnater.New()
		tbl := table.New("Protocol", "Local", "NAT Port", "Remote", "Last Seen")
		natTable, err := x.NatTable()
		if err != nil {
			log.Fatalf("Can´t get NAT table: %s", err)
		}
		for _, entry := range natTable {
			tbl.AddRow(
				entry.Protocol.String(),
				fmt.Sprintf("%s:%d", entry.Saddr, entry.Source),
				fmt.Sprintf("%d", entry.NatPort),
				fmt.Sprintf("%s:%d", entry.Daddr, entry.Dest),
				entry.LastSeen,
			)
		}
		tbl.Print()
	},
}

func init() {
	natTableCmd.AddCommand(showCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// showCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// showCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
