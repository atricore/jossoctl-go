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
			return defaultIdSourceTableFormat
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
`
		}
	}

	format := Format(source)
	return format
}

func VaultWrite(ctx IdSourceContext, dbvault []api.EmbeddedIdentityVaultDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return VaultFormat(ctx, dbvault, format)
	}
	return ctx.Write(newVaultWrapper(), render)

}

func VaultFormat(ctx IdSourceContext, dbvault []api.EmbeddedIdentityVaultDTO, format func(subContext SubContext) error) error {
	for _, dbvault := range dbvault {
		var formatted []SubContext
		formatted = []SubContext{}
		c := vaultWrapper{
			p: &dbvault,
		}
		formatted = append(formatted, &c)

		for _, dbvaultCtx := range formatted {
			if err := format(dbvaultCtx); err != nil {
				return err
			}
		}
	}
	return nil
}

func newVaultWrapper() *vaultWrapper {
	vaultWrapper := vaultWrapper{}
	vaultWrapper.Header = SubHeaderContext{
		"Name": nameHeader,
		"Type": typeHeader,
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
	return c.p.GetIdentityConnectorName()
}
