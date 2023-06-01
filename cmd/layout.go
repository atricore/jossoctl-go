/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"github.com/spf13/cobra"
)

// LayoutCmd represents the Layout command
var layoutCmd = &cobra.Command{
	Use:   "layout",
	Short: "layout identity appliance",
	Long: `Layout identity appliance.
	
SYNTAX
	appliance:layout [options] appliance id/name`,
	Run: func(cmd *cobra.Command, args []string) {
		layoutAppliance(id_or_name)
	},
}

func init() {
	rootCmd.AddCommand(layoutCmd)

	layoutCmd.Flags().StringP("out", "o", "", "Export layout as graph")

}

func layoutAppliance(id_or_name string) error {
	content, err := Client.Client().CalcLayout(id_or_name)
	if err != nil {
		return err
	}
	printOut(content)
	return nil

}
