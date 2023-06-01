package render

import (
	"fmt"
	"io"

	api "github.com/atricore/josso-api-go"
	"github.com/atricore/josso-cli-go/cli"
	"github.com/atricore/josso-cli-go/render/formatter"
)

func RenderApplianceToFile(c cli.Cli, id_or_name string, source string, quiet bool, fName string, replace bool) error {
	var f = func(out io.Writer) {
		RenderApplianceToWriter(c, id_or_name, source, quiet, out)
	}

	return RenderToFile(f, fName, replace)
}

func RenderApplianceToWriter(c cli.Cli, id_or_name string, source string, quiet bool, out io.Writer) {

	a, err := c.Client().GetApplianceContainer(id_or_name)
	if err != nil {
		c.Error(err)
		return
	}

	if a.Appliance == nil {
		c.Error(fmt.Errorf("appliance not found: %s", id_or_name))
		return
	}

	ctx := formatter.ApplianceContext{
		Client: c,
		Context: formatter.Context{
			Output: out,
			Format: formatter.NewApplianceFormat(source, quiet),
		},
	}

	lsa := []api.IdentityApplianceContainerDTO{a}
	err = formatter.ApplianceWrite(ctx, lsa)
	if err != nil {
		ctx.Client.Error(err)
	}
}
