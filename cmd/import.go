/*
Copyright © 2022 atricore <sgonzalez@atricore.com>
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
}
