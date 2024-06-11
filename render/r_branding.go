package render

import (
	"io"

	api "github.com/atricore/josso-api-go"
	"github.com/atricore/josso-cli-go/cli"
	"github.com/atricore/josso-cli-go/render/formatter"
)

func RenderBrandingToFile(c cli.Cli, brandingName string, _ string, source string, quiet bool, fName string, replace bool) error {
	var f = func(out io.Writer) {
		RenderBrandingToWriter(c, brandingName, brandingName, source, quiet, out)
	}

	return RenderToFile(f, fName, replace)
}

// c cli.Cli, idaName string, idaName1 string, source string, quiet bool, out io.Writer
func RenderBrandingToWriter(c cli.Cli, brandingName string, brandingName1 string, source string, quiet bool, out io.Writer) error {

	a, err := c.Client().GetBrandingDefinitionDTO(brandingName)
	if err != nil {
		return err
	}

	ctx := formatter.BrandingContext{
		Client: c,
		Context: formatter.Context{
			Output: out,
			Format: formatter.NewBrandingFormat(source, quiet),
		},
	}

	lsa := []api.CustomBrandingDefinitionDTO{a}
	return formatter.BrandingWrite(ctx, lsa)
}
