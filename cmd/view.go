/*
Copyright © 2022 atricore <sgonzalez@atricore.com>
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
	Args:    cobra.ExactArgs(0),
	Long: `Displays detailed information about a resource. For example:

You can use the view command to display details  about an identity appliance, an identity provider, an identity source, etc.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("select a resource type to view, for example: view provider")
	},
}

func init() {
	rootCmd.AddCommand(viewCmd)
	viewCmd.PersistentFlags().BoolVarP(&print_raw, "raw", "r", false, "Display raw content")
}
