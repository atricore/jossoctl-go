/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Import represents the Import command
var importCmd = &cobra.Command{
	Use:     "import",
	Aliases: []string{"i"},
	Short:   "import resource details",
	Args:    cobra.ExactArgs(1),
	Long: `Import detailed information about a resource. For example:

You can use the import command to import appliance or import definition`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("import called")
	},
}

func init() {
	rootCmd.AddCommand(importCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	importCmd.PersistentFlags().BoolVarP(&print_raw, "raw", "r", false, "Display raw content")
}
