/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/spf13/cobra"
)

// LayoutCmd represents the Layout command
var iayoutCmd = &cobra.Command{
	Use:   "layout",
	Short: "layout identity appliance",
	Long:  `Layout identity appliance.`,

	Args: cobra.MaximumNArgs(1),
}

func init() {
	rootCmd.AddCommand(iayoutCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
