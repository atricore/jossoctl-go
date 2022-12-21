/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ExportProviderCmd represents the ExportProvider command
var exportProviderCmd = &cobra.Command{
	Use:        "provider-md name",
	ArgAliases: []string{"provider-name"},
	Short:      "Export provider metadata to a file",
	Long: `Export metadat for the give provider's name to a file.

SYNTAX
	appliance:export-provider-metadata [options] appliance id/name name`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(fmt.Sprintf("TODO! %s", args[0]))
	},
}

func init() {
	exportCmd.AddCommand(exportProviderCmd)
	exportProviderCmd.Flags().BoolP("replace", "r", false, "replace the file if it exists")
	exportProviderCmd.Flags().StringP("out", "o", "", "output metadata file")
	exportProviderCmd.Flags().StringP("provider", "p", "", "provider which metadata to export")
}
