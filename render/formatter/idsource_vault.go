package formatter

import (
	"strconv"

	api "github.com/atricore/josso-api-go"
)

const (
	vaultTFFormat = `resource "iamtf_idvault" "{{.Name}}" {
		name = "{{.Name}}"
  }`
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

type idVaultWrapper struct {
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
	case TFFormatKey:
		return vaultTFFormat
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

func VaultFormat(ctx IdSourceContext, idVaults []api.EmbeddedIdentityVaultDTO, format func(subContext SubContext) error) error {
	for _, idVault := range idVaults {
		c := idVaultWrapper{
			p:     &idVault,
			trunc: false,
		}
		if err := format(&c); err != nil {
			return err
		}
	}
	return nil
}

func newVaultWrapper() *idVaultWrapper {
	vaultWrapper := idVaultWrapper{}
	vaultWrapper.Header = SubHeaderContext{
		"Name": nameHeader,
		"Type": typeHeader,
	}
	return &vaultWrapper
}

func (c *idVaultWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *idVaultWrapper) ID() string {

	id := strconv.FormatInt(c.p.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

// General
func (c *idVaultWrapper) Name() string {
	return c.p.GetName()
}

func (c *idVaultWrapper) Id() int64 {
	return c.p.GetId()
}

func (c *idVaultWrapper) Description() string {

	return c.p.GetDescription()
}

// connector

func (c *idVaultWrapper) ConnectorName() string {
	return c.p.GetIdentityConnectorName()
}
