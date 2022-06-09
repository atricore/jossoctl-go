package formatter

import (
	"strconv"

	api "github.com/atricore/josso-api-go"
	cli "github.com/atricore/josso-sdk-go"
)

type idPWrapper struct {
	HeaderContext
	trunc bool
	p     *api.IdentityProviderDTO
}

const (
	idpPrettyFormat = `Name:		{{.Name}}
`
)

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewIdPFormat(source string, quiet bool) Format {
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

func IdPWrite(ctx ProviderContext, providers []api.IdentityProviderDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return idpFormat(ctx, providers, format)
	}
	return ctx.Write(newIdPWrapper(), render)

}

func idpFormat(ctx ProviderContext, providers []api.IdentityProviderDTO, format func(subContext SubContext) error) error {
	for _, provider := range providers {
		var formatted []SubContext
		formatted = []SubContext{}
		c := idPWrapper{
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

func newIdPWrapper() *idPWrapper {
	idpWrapper := idPWrapper{}
	idpWrapper.Header = SubHeaderContext{
		"Name":     nameHeader,
		"Type":     typeHeader,
		"Location": locationHeader,
	}
	return &idpWrapper
}

func (c *idPWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *idPWrapper) ID() string {

	id := strconv.FormatInt(c.p.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

func (c *idPWrapper) Name() string {
	return c.p.GetName()
}

func (c *idPWrapper) Type() string {
	return api.AsString(c.p.AdditionalProperties["@c"], "N/A")
}

func (c *idPWrapper) Location() string {
	return cli.LocationToStr(c.p.Location)
}

func (c *idPWrapper) Description() string {
	return c.p.GetDescription()
}
