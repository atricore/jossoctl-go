package render

import (
	"fmt"
	"io"

	api "github.com/atricore/josso-api-go"
	"github.com/atricore/josso-cli-go/cli"
	"github.com/atricore/josso-cli-go/render/formatter"
)

func RenderApplianceToFile(c cli.Cli, idaName string, source string, quiet bool, fName string, replace bool) error {
	var f = func(out io.Writer) {
		RenderApplianceToWriter(c, idaName, source, quiet, out)
	}

	return RenderToFile(f, fName, replace)
}

func RenderApplianceToWriter(c cli.Cli, idaName string, source string, quiet bool, out io.Writer) error {

	a, err := c.Client().GetApplianceContainer(idaName)
	if err != nil {
		return err
	}

	if a.Appliance == nil {
		return fmt.Errorf("appliance %s not found", idaName)
	}

	ctx := formatter.ApplianceContext{
		Client: c,
		Context: formatter.Context{
			Output: out,
			Format: formatter.NewApplianceFormat(source, quiet),
		},
	}

	lsa := []api.IdentityApplianceContainerDTO{a}
	return formatter.ApplianceWrite(ctx, lsa)
}
