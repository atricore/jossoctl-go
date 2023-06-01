package render

import (
	"fmt"
	"io"
	"os"

	api "github.com/atricore/josso-api-go"
	"github.com/atricore/josso-cli-go/cli"
	"github.com/atricore/josso-cli-go/render/formatter"
)

var IdSourcesFormatters = []formatter.IdSourceFormatter{
	{
		IdSourceType:   "DbIdentitySource",
		IdSourceFormat: formatter.NewDbIdSouceFormat,
		IdSourceWriter: func(ctx formatter.IdSourceContext, id_or_name string, containers []api.IdSourceContainerDTO) error {
			var idsource []api.DbIdentitySourceDTO
			for _, c := range containers {
				if c.GetType() == "DbIdentitySource" {
					db, err := ctx.Client.Client().GetDbIdentitySourceDTO(id_or_name, c.GetName())
					if err != nil {
						return err
					}
					idsource = append(idsource, db)
				}
			}

			return formatter.IdSourceDBWrite(ctx, idsource)
		},
	},
	{
		IdSourceType:   "EmbeddedIdentityVault",
		IdSourceFormat: formatter.NewIdVaultFormat,
		IdSourceWriter: func(ctx formatter.IdSourceContext, id_or_name string, containers []api.IdSourceContainerDTO) error {
			var Embeddedidsource []api.EmbeddedIdentityVaultDTO
			for _, c := range containers {
				if c.GetType() == "EmbeddedIdentityVault" {
					emd, err := ctx.Client.Client().GetIdVault(id_or_name, c.GetName())
					if err != nil {
						return err
					}
					Embeddedidsource = append(Embeddedidsource, emd)
				}
			}
			return formatter.VaultWrite(ctx, Embeddedidsource)
		},
	},
	{
		IdSourceType:   "LdapIdentitySource",
		IdSourceFormat: formatter.NewLdapFormat,
		IdSourceWriter: func(ctx formatter.IdSourceContext, id_or_name string, containers []api.IdSourceContainerDTO) error {
			var Ldapidsource []api.LdapIdentitySourceDTO
			for _, c := range containers {
				if c.GetType() == "LdapIdentitySource" {
					ldap, err := ctx.Client.Client().GetIdSourceLdap(id_or_name, c.GetName())
					if err != nil {
						return err
					}
					Ldapidsource = append(Ldapidsource, ldap)
				}
			}
			return formatter.LdapWrite(ctx, Ldapidsource)
		},
	},
}

var DefaultIdSourcesFormatters = formatter.IdSourceFormatter{
	IdSourceType:   "__default__",
	IdSourceFormat: formatter.NewIdSourceContainerFormat,
	IdSourceWriter: func(ctx formatter.IdSourceContext, id_or_name string, containers []api.IdSourceContainerDTO) error {
		var idsources []api.IdentitySourceDTO

		for _, c := range containers {
			idsources = append(idsources, *c.IdSource)
		}
		return formatter.IdSourceWrite(ctx, idsources)
	},
}

func RenderIDSourceToFile(c cli.Cli, id_or_name string, pName string, source string, quiet bool, fName string, replace bool) error {
	var f = func(out io.Writer) {
		RenderIDSourceToWriter(c, id_or_name, pName, source, quiet, out)
	}

	return RenderToFile(f, fName, replace)
}

func RenderIDSourceToWriter(c cli.Cli, id_or_name string, idSrcName string, source string, quiet bool, out io.Writer) {
	p, err := c.Client().GetIdSource(id_or_name, idSrcName)
	if err != nil {
		c.Error(err)
		os.Exit(1)
	}

	if p.Name == nil {
		c.Error(fmt.Errorf("idsource %s not found in appliance %s", idSrcName, id_or_name))
		os.Exit(1)
	}

	f := getIdSourcesFormatter(p.GetType())

	ctx := formatter.IdSourceContext{
		Context: formatter.Context{
			Output: out,
			Format: f.IdSourceFormat(source, quiet),
		},
	}

	lsa := []api.IdSourceContainerDTO{p}
	err = f.IdSourceWriter(ctx, id_or_name, lsa)
	if err != nil {
		c.Error(err)
		os.Exit(1)
	}
}

func getIdSourcesFormatter(pType string) formatter.IdSourceFormatter {

	for _, f := range IdSourcesFormatters {
		if f.IdSourceType == pType {
			return f
		}
	}

	return DefaultIdSourcesFormatters
}
