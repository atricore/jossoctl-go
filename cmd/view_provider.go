/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"
	"os"

	"github.com/atricore/josso-cli-go/formatter"
	"github.com/spf13/cobra"

	api "github.com/atricore/josso-api-go"
)

var ProviderFormatters = []formatter.ProviderFormatter{
	{
		PType:   "IdentityProvider",
		PFormat: formatter.NewIdPFormat,
		PWriter: func(ctx formatter.ProviderContext, containers []api.ProviderContainerDTO) error {
			var providers []api.IdentityProviderDTO
			for _, c := range containers {
				if c.GetType() == "IdentityProvider" {
					p, err := client.Client().GetIdp(id_or_name, c.GetName())
					if err != nil {
						return err
					}
					providers = append(providers, p)
				}
			}

			formatter.IdPWrite(ctx, providers)
			return nil
		},
	},
	{
		PType:   "InternalSaml2ServiceProvider",
		PFormat: formatter.NewIntSaml2SpFormat,
		PWriter: func(ctx formatter.ProviderContext, containers []api.ProviderContainerDTO) error {
			var providers []api.InternalSaml2ServiceProviderDTO
			for _, c := range containers {
				if c.GetType() == "InternalSaml2ServiceProvider" {
					p, err := client.Client().GetIntSaml2Sp(id_or_name, c.GetName())
					if err != nil {
						return err
					}
					providers = append(providers, p)
				}
			}
			formatter.IntSaml2SpWrite(ctx, providers)
			return nil
		},
	},
}

var DefaultProviderFormatters = formatter.ProviderFormatter{
	PType:   "__default__",
	PFormat: formatter.NewProviderContainerFormat,
	PWriter: func(ctx formatter.ProviderContext, containers []api.ProviderContainerDTO) error {
		var providers []api.FederatedProviderDTO

		for _, c := range containers {
			providers = append(providers, *c.FederatedProvider)
		}
		formatter.ProviderWrite(ctx, providers)

		return nil
	},
}

// appliancesCmd represents the appliances command
var viewProviderCmd = &cobra.Command{
	Use:     "provider",
	Aliases: []string{"p"},
	Short:   "view provider",
	Long:    `view federated provider`,
	Run:     viewProvider,
	Args:    cobra.ExactArgs(1),
}

func viewProvider(cmd *cobra.Command, args []string) {
	p, err := client.Client().GetProvider(id_or_name, args[0])
	if err != nil {
		client.Error(err)
		os.Exit(1)
	}

	if p.Name == nil {
		client.Error(fmt.Errorf("provider! %s not found in appliance %s", args[0], id_or_name))
		os.Exit(1)
	}

	source := func() string {
		if print_raw {
			return "raw"
		}
		return "pretty"
	}

	f := getFormatter(p.GetType())

	ctx := formatter.ProviderContext{
		Context: formatter.Context{
			Output: client.Out(),
			Format: f.PFormat(source(), quiet),
		},
	}

	lsa := []api.ProviderContainerDTO{p}
	err = f.PWriter(ctx, lsa)
	if err != nil {
		client.Error(err)
		os.Exit(1)
	}
}

func init() {
	viewCmd.AddCommand(viewProviderCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// appliancesCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// appliancesCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func getFormatter(pType string) formatter.ProviderFormatter {

	for _, f := range ProviderFormatters {
		if f.PType == pType {
			return f
		}
	}

	return DefaultProviderFormatters
}
