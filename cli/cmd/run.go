/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/julsemaan/ebpf-router/xdpnater"
	"github.com/spf13/cobra"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		x := xdpnater.New()
		x.NatInterface = natInterface
		x.NatIP = natIp
		x.Run()
	},
}

var natInterface string
var natIp string

func init() {
	rootCmd.AddCommand(runCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// runCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	runCmd.Flags().StringVarP(&natIp, "nat-ip", "i", "", "The IP address used for NATing. Will use the first address of the NAT interface if unspecified")
	runCmd.Flags().StringVarP(&natInterface, "nat-interface", "d", "", "The IP address used for NATing. Will use the first address of the NAT interface if unspecified")
}
