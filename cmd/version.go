/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "prints command version",
	Long:  `the version of the ctl command.`,
	Run: func(cmd *cobra.Command, args []string) {
		versionCobra(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func versionCobra(cmd *cobra.Command, args []string) {
	version()
}

func version() {
	fmt.Printf("v%s \n", VERSION)
}
