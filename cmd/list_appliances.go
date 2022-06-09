/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/atricore/josso-cli-go/formatter"
	"github.com/spf13/cobra"
)

// appliancesCmd represents the appliances command
var listAppliancesCmd = &cobra.Command{
	Use:     "appliances",
	Aliases: []string{"apps"},
	Short:   "list appliances",
	Long:    `list identity appliances`,
	Run:     listAppliancesCobra,
	Args:    cobra.MaximumNArgs(0),
}

func listAppliancesCobra(cmd *cobra.Command, args []string) {
	listAppliances()
}

func listAppliances() {
	lsa, err := client.Client().GetApplianceContainers()
	if err != nil {
		client.Error(err)
	}

	source := func() string {
		if print_raw {
			return "raw"
		}
		return "table"
	}

	ctx := formatter.ApplianceContext{
		Context: formatter.Context{
			Output: client.Out(),
			Format: formatter.NewApplianceFormat(source(), quiet),
		},
	}
	err = formatter.ApplianceWrite(ctx, lsa)
	if err != nil {
		client.Error(err)
	}

}

func init() {
	listCmd.AddCommand(listAppliancesCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// appliancesCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// appliancesCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
