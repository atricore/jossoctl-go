/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
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
	a, err := client.Client().GetProviders(id_or_name)
	if err != nil {
		client.Error(err)
		return
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
	}
}

func init() {
	listCmd.AddCommand(listProvidersCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// appliancesCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// appliancesCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
