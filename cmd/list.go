/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all resources of a given type",
	Args:    cobra.MaximumNArgs(0),
	Long: `List all resources of a given type, for example:
	
	You can list identity applances, providers, identity sources, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("list called")
	},
}

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.PersistentFlags().BoolVarP(&print_raw, "raw", "r", false, "Display raw content")
	listAppliancesCmd.Flags().BoolP("state", "s", false, "List appliance in the specified states")
}
