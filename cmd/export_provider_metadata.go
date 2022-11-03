/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ExportProviderCmd represents the ExportProvider command
var exportProviderCmd = &cobra.Command{
	Use:   "provider-md",
	Short: "Export provider metadata to a file",
	Long: `Export metadat for the give provider (SAML, OIDC, etc).

SYNTAX
	appliance:export-provider-metadata [options] appliance id/name name`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO!")
	},
}

func init() {
	exportCmd.AddCommand(exportProviderCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	exportProviderCmd.Flags().BoolP("replace", "r", false, "Replace out file")
	exportProviderCmd.Flags().StringP("out", "o", "", "Path to new metadata file")
	exportAgentCfgCmd.Flags().StringP("target-provider", "t", "", "Target provider, useful if a specific metadata is required for this provider")
}
