/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/spf13/cobra"
)

// UndeployCmd represents the Undeploy command
var undeployCmd = &cobra.Command{
	Use:   "undeploy",
	Short: "undeploy identity appliance",
	Long:  `Undeploy identity appliance.`,

	Args: cobra.MaximumNArgs(1),
}

func init() {
	rootCmd.AddCommand(undeployCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
