/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ExportDefinitionCmd represents the ExportDefinition command
var exportDefinitionCmd = &cobra.Command{
	Use:   "appliance",
	Short: "Export Identity Appliance definition",
	Long: `Export definition identity appliance.
	
SYNTAX
	appliance:export-definition [options] appliance id/name`,

	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO!")
	},
}

func init() {
	exportCmd.AddCommand(exportDefinitionCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	exportDefinitionCmd.Flags().BoolP("replace", "r", false, "Replace out file")
	exportDefinitionCmd.Flags().StringP("output", "o", "", "Agent configuration destination file")
}
