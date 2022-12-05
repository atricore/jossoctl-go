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

			return formatter.IdPWrite(ctx, providers)
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
			return formatter.IntSaml2SpWrite(ctx, providers)
		},
	},
	{
		PType:   "ExternalOpenIDConnectRelayingParty",
		PFormat: formatter.NewOidcRpFormat,
		PWriter: func(ctx formatter.ProviderContext, containers []api.ProviderContainerDTO) error {
			var providers []api.ExternalOpenIDConnectRelayingPartyDTO
			for _, c := range containers {
				if c.GetType() == "ExternalOpenIDConnectRelayingParty" {
					p, err := client.Client().GetOidcRp(id_or_name, c.GetName())
					if err != nil {
						return err
					}
					providers = append(providers, p)
				}
			}
			return formatter.OidcRpWrite(ctx, providers)
		},
	},
}

var DefaultProviderFormatter = formatter.ProviderFormatter{
	PType:   "__default__",
	PFormat: formatter.NewProviderContainerFormat,
	PWriter: func(ctx formatter.ProviderContext, containers []api.ProviderContainerDTO) error {
		var providers []api.FederatedProviderDTO
		for _, c := range containers {
			if c.FederatedProvider != nil {
				providers = append(providers, *c.FederatedProvider)
			} else {
				printError(fmt.Errorf("provider %s found, but view is not supported", *c.Name))
			}
		}
		return formatter.ProviderWrite(ctx, providers)
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
}

func getFormatter(pType string) formatter.ProviderFormatter {

	for _, f := range ProviderFormatters {
		if f.PType == pType {
			return f
		}
	}

	return DefaultProviderFormatter
}
