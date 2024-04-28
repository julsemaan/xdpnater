/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"strings"

	"github.com/julsemaan/ebpf-router/xdpnater"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Runs the XDP nater",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		x := xdpnater.New()
		x.NatInterface = natInterface
		x.NatIP = natIp
		if interfaces != "" {
			x.Interfaces = strings.Split(interfaces, ",")
		}
		x.Run()
	},
}

var natInterface string
var natIp string
var interfaces string

func init() {
	rootCmd.AddCommand(runCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// runCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	runCmd.Flags().StringVarP(&natIp, "nat-ip", "i", "", "The IP address used for NATing. Will use the first address of the NAT interface if unspecified")
	runCmd.Flags().StringVarP(&natInterface, "nat-interface", "d", "", "The interface used for NATing. Will use the interface of the default gateway if not specified.")
	runCmd.Flags().StringVarP(&interfaces, "interfaces", "n", "", "A comma-delimited list of interfaces to listen on. Defaults to all if not specified.")
}
