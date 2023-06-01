package render

import (
	"fmt"
	"io"
	"os"

	api "github.com/atricore/josso-api-go"
	"github.com/atricore/josso-cli-go/cli"
	"github.com/atricore/josso-cli-go/render/formatter"
)

var ProviderFormatters = []formatter.ProviderFormatter{
	{
		PType:   "IdentityProvider",
		PFormat: formatter.NewIdPFormat,
		PWriter: func(ctx formatter.ProviderContext, id_or_name string, containers []api.ProviderContainerDTO) error {
			var providers []api.IdentityProviderDTO
			for _, c := range containers {
				if c.GetType() == "IdentityProvider" {
					p, err := ctx.Client.Client().GetIdp(id_or_name, c.GetName())
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
		PWriter: func(ctx formatter.ProviderContext, id_or_name string, containers []api.ProviderContainerDTO) error {
			var providers []api.InternalSaml2ServiceProviderDTO
			for _, c := range containers {
				if c.GetType() == "InternalSaml2ServiceProvider" {
					p, err := ctx.Client.Client().GetIntSaml2Sp(id_or_name, c.GetName())
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
		PWriter: func(ctx formatter.ProviderContext, id_or_name string, containers []api.ProviderContainerDTO) error {
			var providers []api.ExternalOpenIDConnectRelayingPartyDTO
			for _, c := range containers {
				if c.GetType() == "ExternalOpenIDConnectRelayingParty" {
					p, err := ctx.Client.Client().GetOidcRp(id_or_name, c.GetName())
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
	PWriter: func(ctx formatter.ProviderContext, id_or_name string, containers []api.ProviderContainerDTO) error {
		var providers []api.FederatedProviderDTO
		for _, c := range containers {
			if c.FederatedProvider != nil {
				providers = append(providers, *c.FederatedProvider)
			} else {
				return fmt.Errorf("provider %s found, but view is not supported", *c.Name)
			}
		}
		return formatter.ProviderWrite(ctx, providers)
	},
}

func RenderProviderToFile(c cli.Cli, id_or_name string, pName string, source string, quiet bool, fName string, replace bool) error {
	var f = func(out io.Writer) {
		RenderProviderToWriter(c, id_or_name, pName, source, quiet, out)
	}

	return RenderToFile(f, fName, replace)
}

func RenderProviderToWriter(c cli.Cli, id_or_name string, pName string, source string, quiet bool, out io.Writer) {

	p, err := c.Client().GetProvider(id_or_name, pName)
	if err != nil {
		c.Error(err)
		os.Exit(1)
	}

	if p.Name == nil {
		c.Error(fmt.Errorf("provider! %s not found in appliance %s", pName, id_or_name))
		os.Exit(1)
	}

	f := GetProviderFormatter(p.GetType())
	ctx := formatter.ProviderContext{
		Context: formatter.Context{
			Output: out,
			Format: f.PFormat(source, quiet),
		},
	}

	lsa := []api.ProviderContainerDTO{p}
	err = f.PWriter(ctx, id_or_name, lsa)
	if err != nil {
		ctx.Client.Error(err)
		os.Exit(1)
	}
}

func GetProviderFormatter(pType string) formatter.ProviderFormatter {

	for _, f := range ProviderFormatters {
		if f.PType == pType {
			return f
		}
	}

	return DefaultProviderFormatter
}
