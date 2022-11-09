package formatter

import (
	"strconv"

	api "github.com/atricore/josso-api-go"
)

const (
	vaultPrettyFormat = `
Idvault (built-in)
    	
General:
        Name:	{{.Name}}
        ID:		{{.Id}}
        Documentation:	{{.Description}}
		
    	Connector 
        Name:	{{.ConnectorName}}
`
)

type vaultWrapper struct {
	HeaderContext
	trunc bool
	p     *api.EmbeddedIdentityVaultDTO
}

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewIdVaultFormat(source string, quiet bool) Format {
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
			return vaultPrettyFormat
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

func VaultWrite(ctx ProviderContext, providers []api.EmbeddedIdentityVaultDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return VaultFormat(ctx, providers, format)
	}
	return ctx.Write(newVaultWrapper(), render)

}

func VaultFormat(ctx ProviderContext, providers []api.EmbeddedIdentityVaultDTO, format func(subContext SubContext) error) error {
	for _, provider := range providers {
		var formatted []SubContext
		formatted = []SubContext{}
		c := vaultWrapper{
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

func newVaultWrapper() *vaultWrapper {
	vaultWrapper := vaultWrapper{}
	vaultWrapper.Header = SubHeaderContext{
		"Name":     nameHeader,
		"Type":     typeHeader,
		"Location": locationHeader,
	}
	return &vaultWrapper
}

func (c *vaultWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *vaultWrapper) ID() string {

	id := strconv.FormatInt(c.p.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

// General
func (c *vaultWrapper) Name() string {
	return c.p.GetName()
}

func (c *vaultWrapper) Id() int64 {
	return c.p.GetId()
}

func (c *vaultWrapper) Description() string {

	return c.p.GetDescription()
}

// connector

func (c *vaultWrapper) ConnectorName() string {
	return *c.p.IdentityConnectorName
}
