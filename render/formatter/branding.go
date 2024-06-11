package formatter

import (
	"strconv"

	api "github.com/atricore/josso-api-go"
	cmdcli "github.com/atricore/josso-cli-go/cli"
)

const (
	defaultBrandingTableFormat  = "table {{.ID}} / {{.WebBrandingId}}\t{{.Name}}\t{{.Type}}"
	defaultBrandingPrettyFormat = `
ID           :          {{.ID}}/{{.WebBrandingId}}
Name         :  {{.Name}}
URI          :  {{.BundleUri}}
App Class    :  {{.SsoAppClazz}}
IdP App Class:  {{.SsoAppClazz}}
IdP App Class:  {{.SsoIdPOidcClazz}}
`

	brandingIDHeader    = "ID"
	webBrandingIdHeader = "ID"
)

// BrandingContext contains appliance specific information required by the formatter, encapsulate a Context struct.
type BrandingContext struct {
	Client cmdcli.Cli
	Context
}

type brandingWrapper struct {
	HeaderContext
	trunc bool
	a     api.CustomBrandingDefinitionDTO
}

// NewBrandingFormat returns a format for rendering an BrandingContext
func NewBrandingFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultBrandingTableFormat
		}
	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultBrandingPrettyFormat
		}
	case RawFormatKey:
		switch {
		case quiet:
			return `branding_id: {{.ID}}`
		default:
			return `branding_id: {{.ID}}
name: {{.Name}}
`
		}
	}

	format := Format(source)
	return format
}

// BrandingWrite writes the formatter appliances using the BrandingContext
func BrandingWrite(ctx BrandingContext, appliances []api.CustomBrandingDefinitionDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return brandingFormat(ctx, appliances, format)
	}
	return ctx.Write(newBrandingWrapper(), render)
}

func brandingFormat(ctx BrandingContext, brandings []api.CustomBrandingDefinitionDTO, format func(subContext SubContext) error) error {
	for _, branding := range brandings {
		formatted := []*brandingWrapper{}

		c := brandingWrapper{
			a:     branding,
			trunc: false,
		}

		formatted = append(formatted, &c)

		for _, brandingCtx := range formatted {
			if err := format(brandingCtx); err != nil {
				return err
			}
		}
	}
	return nil
}

func newBrandingWrapper() *brandingWrapper {
	brandingCtx := brandingWrapper{}
	brandingCtx.Header = SubHeaderContext{
		"ID":            applianceIDHeader,
		"WebBrandingId": webBrandingIdHeader,
		"Name":          nameHeader,
		"Type":          typeHeader,
	}
	return &brandingCtx
}

func (c *brandingWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *brandingWrapper) ID() string {

	id := strconv.FormatInt(c.a.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

func (c *brandingWrapper) Name() string {
	return c.a.GetName()
}

func (c *brandingWrapper) BundleSymbolicName() string {
	return c.a.GetBundleSymbolicName()
}

func (c *brandingWrapper) BundleUri() string {
	return c.a.GetBundleUri()
}

func (c *brandingWrapper) WebBrandingId() string {
	return c.a.GetWebBrandingId()
}

func (c *brandingWrapper) SsoIdPOidcClazz() string {
	return c.a.GetCustomOpenIdAppClazz()
}

func (c *brandingWrapper) SsoIdPClazz() string {
	return c.a.GetCustomSsoIdPAppClazz()
}

func (c *brandingWrapper) SsoAppClazz() string {
	return c.a.GetCustomSsoAppClazz()
}

func (c *brandingWrapper) Type() string {
	return c.a.GetType()
}

func (c *brandingWrapper) Resource() string {
	return c.a.GetResource()
}

func (c *brandingWrapper) Description() string {
	return c.a.GetDescription()
}
