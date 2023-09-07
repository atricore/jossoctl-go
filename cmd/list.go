/*
Copyright © 2022 atricore <sgonzalez@atricore.com>
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
	
	You can list identity appliances, providers, idsources, etc.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("select a resource type to view, for example: list providers")
	},
}

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.PersistentFlags().BoolVarP(&print_raw, "raw", "r", false, "Display raw content")
	listAppliancesCmd.Flags().BoolP("state", "s", false, "List appliance in the specified states")
}
