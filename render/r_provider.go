package render

import (
	"fmt"
	"io"

	api "github.com/atricore/josso-api-go"
	"github.com/atricore/josso-cli-go/cli"
	"github.com/atricore/josso-cli-go/render/formatter"
)

var ProviderFormatters = []formatter.ProviderFormatter{
	{
		PType:   "IdentityProvider",
		PFormat: formatter.NewIdPFormat,
		PWriter: func(ctx formatter.ProviderContext, idaName string, containers []api.ProviderContainerDTO) error {
			var providers []api.IdentityProviderDTO
			for _, c := range containers {
				if c.GetType() == "IdentityProvider" {
					p, err := ctx.Client.Client().GetIdp(idaName, c.GetName())
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
		PWriter: func(ctx formatter.ProviderContext, idaName string, containers []api.ProviderContainerDTO) error {
			var providers []formatter.IntSaml2SpWrapper
			for _, container := range containers {
				if container.GetType() == "InternalSaml2ServiceProvider" {
					provider, err := ctx.Client.Client().GetIntSaml2Sp(idaName, container.GetName())
					if err != nil {
						return err
					}

					jossoResource, err := ctx.Client.Client().GetJosso1Resource(idaName, *provider.GetServiceConnection().Name)
					if err != nil {
						return err
					}

					// create instance of IntSaml2SpWrapper
					w := formatter.IntSaml2SpWrapper{
						IdaName:   ctx.IdaName,
						Container: &container,
						Provider:  &provider,
						Resource:  &jossoResource,
					}

					providers = append(providers, w)
				}
			}
			return formatter.IntSaml2SpWrite(ctx, providers)
		},
	},
	{
		PType:   "ExternalOpenIDConnectRelayingParty",
		PFormat: formatter.NewOidcRpFormat,
		PWriter: func(ctx formatter.ProviderContext, idaName string, containers []api.ProviderContainerDTO) error {
			var providers []api.ExternalOpenIDConnectRelayingPartyDTO
			for _, c := range containers {
				if c.GetType() == "ExternalOpenIDConnectRelayingParty" {
					p, err := ctx.Client.Client().GetOidcRp(idaName, c.GetName())
					if err != nil {
						return err
					}
					providers = append(providers, p)
				}
			}
			return formatter.OidcRpWrite(ctx, providers)
		},
	},
	{
		PType:   "ExternalSaml2ServiceProvider",
		PFormat: formatter.NewExtSaml2SpFormat,
		PWriter: func(ctx formatter.ProviderContext, idaName string, containers []api.ProviderContainerDTO) error {
			var providers []formatter.ExtSaml2SpWrapper
			for _, c := range containers {
				if c.GetType() == "ExternalSaml2ServiceProvider" {
					p, err := ctx.Client.Client().GetExtSaml2Sp(idaName, c.GetName())
					if err != nil {
						return err
					}
					// create instance of IntSaml2SpWrapper
					w := formatter.ExtSaml2SpWrapper{
						IdaName:   ctx.IdaName,
						Container: &c,
						Provider:  &p,
					}

					providers = append(providers, w)
				}
			}
			return formatter.ExtSaml2SpWrite(ctx, providers)
		},
	},
}

var DefaultProviderFormatter = formatter.ProviderFormatter{
	PType:   "__default__",
	PFormat: formatter.NewProviderContainerFormat,
	PWriter: func(ctx formatter.ProviderContext, idaName string, containers []api.ProviderContainerDTO) error {
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

func RenderProviderToFile(c cli.Cli, idaName string, pName string, source string, quiet bool, fName string, replace bool) error {
	var f = func(out io.Writer) {
		RenderProviderToWriter(c, idaName, pName, source, quiet, out)
	}

	return RenderToFile(f, fName, replace)
}

func RenderProviderToWriter(c cli.Cli, idaName string, pName string, source string, quiet bool, out io.Writer) error {

	p, err := c.Client().GetProvider(idaName, pName)
	if err != nil {
		return err
	}

	if p.Name == nil {
		return fmt.Errorf("provider %s not found in appliance %s", pName, idaName)
	}

	f := GetProviderFormatter(p.GetType())
	ctx := formatter.ProviderContext{
		Client:  c,
		IdaName: idaName,
		Context: formatter.Context{
			Output: out,
			Format: f.PFormat(source, quiet),
		},
	}

	lsa := []api.ProviderContainerDTO{p}
	return f.PWriter(ctx, idaName, lsa)
}

func GetProviderFormatter(pType string) formatter.ProviderFormatter {

	for _, f := range ProviderFormatters {
		if f.PType == pType {
			return f
		}
	}

	return DefaultProviderFormatter
}
