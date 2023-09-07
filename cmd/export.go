/*
Copyright © 2022 atricore <sgonzalez@atricore.com>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ExportnCmd represents the Export command
var exportCmd = &cobra.Command{
	Use:     "export",
	Aliases: []string{"e"},
	Short:   "export resource details",
	Long:    `Export detailed information about a resource.`,

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("export called")
	},
}

func init() {
	rootCmd.AddCommand(exportCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
