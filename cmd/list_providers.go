/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"os"

	"github.com/atricore/josso-cli-go/render/formatter"
	"github.com/spf13/cobra"
)

// appliancesCmd represents the appliances command
var listProvidersCmd = &cobra.Command{
	Use:     "providers",
	Aliases: []string{"p"},
	Short:   "list providers",
	Long:    `list providers in an appliance`,
	Run:     listProvidersCobra,
	Args:    cobra.ExactArgs(0),
}

func listProvidersCobra(cmd *cobra.Command, args []string) {
	listProviders()
}

func listProviders() {
	a, err := Client.Client().GetProviders(id_or_name)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}

	source := func() string {
		if print_raw {
			return "raw"
		}
		return "table"
	}

	ctx := formatter.ProviderContext{
		Context: formatter.Context{
			Output: Client.Out(),
			Format: formatter.NewProviderContainerFormat(source(), quiet),
		},
	}
	err = formatter.ProviderContainerWrite(ctx, a)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}
}

func init() {
	listCmd.AddCommand(listProvidersCmd)
}
