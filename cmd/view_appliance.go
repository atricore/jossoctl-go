/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/atricore/josso-cli-go/formatter"
	"github.com/spf13/cobra"

	api "github.com/atricore/josso-api-go"
)

// appliancesCmd represents the appliances command
var viewApplianceCmd = &cobra.Command{
	Use:     "appliance",
	Aliases: []string{"a"},
	Short:   "view appliance",
	Long:    `view identity appliance`,
	Run:     viewAppliances,
}

func viewAppliances(cmd *cobra.Command, args []string) {
	a, err := client.Client().GetApplianceContainer(id_or_name)
	if err != nil {
		client.Error(err)
	}

	source := func() string {
		if print_raw {
			return "raw"
		}
		return "pretty"
	}

	ctx := formatter.ApplianceContext{
		Context: formatter.Context{
			Output: client.Out(),
			Format: formatter.NewApplianceFormat(source(), quiet),
		},
	}

	lsa := []api.IdentityApplianceContainerDTO{a}
	err = formatter.ApplianceWrite(ctx, lsa)
	if err != nil {
		client.Error(err)
	}
}

func init() {
	viewCmd.AddCommand(viewApplianceCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// appliancesCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// appliancesCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
