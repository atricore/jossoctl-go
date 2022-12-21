package cmd /*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/

import (
	"fmt"

	"github.com/spf13/cobra"
)

// testCmd represents the test command
var testCmd = &cobra.Command{
	Use:   "test",
	Short: "test a resource",
	Args:  cobra.MaximumNArgs(0),
	Long:  `test a give resource, for example an identity source connection`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("test called")
	},
}

func init() {
	rootCmd.AddCommand(testCmd)
}
