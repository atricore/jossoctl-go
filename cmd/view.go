/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// listCmd represents the list command
var viewCmd = &cobra.Command{
	Use:     "view",
	Aliases: []string{"v"},
	Short:   "View resource details",
	Args:    cobra.ExactArgs(1),
	Long: `Displays detailed information about a resource. For example:

You can use the view command to display details  about an identity appliance, an identity provider, an identity source, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("view called")
	},
}

func init() {
	rootCmd.AddCommand(viewCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	viewCmd.PersistentFlags().BoolVarP(&print_raw, "raw", "r", false, "Display raw content")
}
