package formatter

import (
	"strconv"

	api "github.com/atricore/josso-api-go"
	cli "github.com/atricore/josso-sdk-go"
)

type IntSaml2SpWrapper struct {
	HeaderContext
	trunc bool
	p     *api.InternalSaml2ServiceProviderDTO
}

const (
	IntSaml2SpPrettyFormat = `Name:		{{.Name}}
Type:		{{.Type}}
Location:	{{.Location}}
Description {{.Description}}
ElementId	{{.ElementId}}
`
)

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewIntSaml2SpFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultProviderTableFormat
		}
	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return idpPrettyFormat
		}
	case RawFormatKey:
		switch {
		case quiet:
			return `name: {{.Name}}`
		default:
			return `name: {{.Name}}
type: {{.Type}}
location: {{.Location}}
`
		}
	}

	format := Format(source)
	return format
}

func IntSaml2SpWrite(ctx ProviderContext, providers []api.InternalSaml2ServiceProviderDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return IntSaml2SpFormat(ctx, providers, format)
	}
	return ctx.Write(newIntSaml2SpWrapper(), render)

}

func IntSaml2SpFormat(ctx ProviderContext, providers []api.InternalSaml2ServiceProviderDTO, format func(subContext SubContext) error) error {
	for _, provider := range providers {
		var formatted []SubContext
		formatted = []SubContext{}
		c := IntSaml2SpWrapper{
			p: &provider,
		}
		formatted = append(formatted, &c)

		for _, providerCtx := range formatted {
			if err := format(providerCtx); err != nil {
				return err
			}
		}
	}
	return nil
}

func newIntSaml2SpWrapper() *IntSaml2SpWrapper {
	IntSaml2SpWrapper := IntSaml2SpWrapper{}
	IntSaml2SpWrapper.Header = SubHeaderContext{
		"Name":     nameHeader,
		"Type":     typeHeader,
		"Location": locationHeader,
	}
	return &IntSaml2SpWrapper
}

func (c *IntSaml2SpWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *IntSaml2SpWrapper) ID() string {

	id := strconv.FormatInt(c.p.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

func (c *IntSaml2SpWrapper) Name() string {
	return c.p.GetName()
}

func (c *IntSaml2SpWrapper) Type() string {
	return api.AsString(c.p.AdditionalProperties["@c"], "N/A")
}

func (c *IntSaml2SpWrapper) Location() string {
	return cli.LocationToStr(c.p.Location)
}

func (c *IntSaml2SpWrapper) Description() string {
	return c.p.GetDescription()
}

func (c *IntSaml2SpWrapper) ElementId() string {
	return c.p.GetElementId()
}
