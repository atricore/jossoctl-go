package render

import (
	api "github.com/atricore/josso-api-go"
	"github.com/atricore/josso-cli-go/render/formatter"
)

var OSGiIBundleFormatters = []formatter.OSGiBundleFormatter{
	{
		Type:   "OSGiIBundle",
		Format: formatter.NewOSGiBundleContainerFormat,
		Writer: func(ctx formatter.OSGiBundleContext, idaName string, containers []api.BundleDescr) error {
			return formatter.OSGiBundleWrite(ctx, containers)
		},
	},
}
