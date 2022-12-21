/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"fmt"
	"os"

	"github.com/atricore/josso-cli-go/formatter"
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
	fmt.Printf("Providers: %v\n", id_or_name)
	a, err := client.Client().GetProviders(id_or_name)
	fmt.Printf("Providers: %v\n", a)
	if err != nil {
		client.Error(err)
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
			Output: client.Out(),
			Format: formatter.NewProviderContainerFormat(source(), quiet),
		},
	}
	err = formatter.ProviderContainerWrite(ctx, a)
	if err != nil {
		client.Error(err)
		os.Exit(1)
	}
}

func init() {
	listCmd.AddCommand(listProvidersCmd)
}
