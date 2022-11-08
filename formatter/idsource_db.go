package formatter

import (
	"strconv"

	api "github.com/atricore/josso-api-go"
	cli "github.com/atricore/josso-sdk-go"
)

const (
	idSourcePrettyFormat = `
DB Identity Source (built-in)
	
General:
    Name:	{{.Name}}
    ID:		{{.Id}}
    Documentation:	{{.Description}}
	
	Connector 

		JDBC Driver:	{{.JdbcDriver}}
		ConnectionUrl:	{{.ConnectionUrl}}
		Username:	
		Password:	{{.Password}}
		Connection pooling:	
		Acquire increment:	{{.AcquireIncrement}}
		Initial pool size:	{{.InitialPool}}
		Min size:	{{.MinSize}}
		Max size:	{{.MaxSize}}
		Idle test period:	{{.IdleConnectionTestPeriod}}
		Mx Idle time :	{{.GetMaxIdleTime}}

	Lookup

		Username query:	{{.UsernameQuery}}
		Roles query:	{{.RolesQuery}}
		Credentials query:	{{.CredentialsQuery}}
		Use result columns as property:	{{.UseColumnNamesAsPropertyNames}}
		Properties query:	{{.PropertiesQuery}}
		Update credentials query:	{{.UpdateCredentials}}
		Relay credentials query:	{{.RelayCredentialQuery}}

	Extension:
		Definition:	{{.}}
	`
)

type DbIdSourceWrapper struct {
	HeaderContext
	trunc bool
	p     *api.DbIdentitySourceDTO
}

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewDbIdSouceFormat(source string, quiet bool) Format {
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
			return idSourcePrettyFormat
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

func IdSourceWrite(ctx ProviderContext, providers []api.DbIdentitySourceDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return IdSourceFormat(ctx, providers, format)
	}
	return ctx.Write(newIdSourceWrapper(), render)

}

func IdSourceFormat(ctx ProviderContext, providers []api.DbIdentitySourceDTO, format func(subContext SubContext) error) error {
	for _, provider := range providers {
		var formatted []SubContext
		formatted = []SubContext{}
		c := DbIdSourceWrapper{
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

func newIdSourceWrapper() *DbIdSourceWrapper {
	DbIdSourceWrapper := DbIdSourceWrapper{}
	DbIdSourceWrapper.Header = SubHeaderContext{
		"Name":     nameHeader,
		"Type":     typeHeader,
		"Location": locationHeader,
	}
	return &DbIdSourceWrapper
}

func (c *DbIdSourceWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *DbIdSourceWrapper) ID() string {

	id := strconv.FormatInt(c.p.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

// General
func (c *DbIdSourceWrapper) Name() string {
	return c.p.GetName()
}

func (c *DbIdSourceWrapper) Id() int64 {
	return c.p.GetId()
}

func (c *DbIdSourceWrapper) Description() string {
	return c.p.GetDescription()
}

// connector

func (c *DbIdSourceWrapper) JdbcDriver() string {
	return c.p.Driver.GetName()
}

func (c *DbIdSourceWrapper) ConnectionUrl() string {
	return c.p.GetConnectionUrl()
}

//func (c *DbIdSourceWrapper) Username() string {
//	return c.p.Get()
//}

func (c *DbIdSourceWrapper) Password() string {
	return c.p.GetPassword()
}

//func (c *DbIdSourceWrapper) ConnectionPooling() string {
//	return c.p.
//}

func (c *DbIdSourceWrapper) AcquireIncrement() int32 {
	return c.p.GetAcquireIncrement()
}

func (c *DbIdSourceWrapper) InitialPool() int32 {
	return c.p.GetInitialPoolSize()
}

func (c *DbIdSourceWrapper) MaxSize() int32 {
	return c.p.GetMaxPoolSize()
}

func (c *DbIdSourceWrapper) MinSize() int32 {
	return c.p.GetMinPoolSize()
}

func (c *DbIdSourceWrapper) IdleConnectionTestPeriod() int32 {
	return c.p.GetIdleConnectionTestPeriod()
}

func (c *DbIdSourceWrapper) MaxIdleTime() int32 {
	return c.p.GetMaxIdleTime()
}

// lookup
func (c *DbIdSourceWrapper) UsernameQuery() string {
	return c.p.GetUserQueryString()
}

func (c *DbIdSourceWrapper) RolesQuery() string {
	rolespointer := c.p.RolesQueryString
	rolesString := cli.StrDeref(rolespointer)
	return rolesString
}

func (c *DbIdSourceWrapper) CredentialsQuery() string {
	return c.p.GetCredentialsQueryString()
}

func (c *DbIdSourceWrapper) UseColumnNamesAsPropertyNames() bool {
	return c.p.GetUseColumnNamesAsPropertyNames()
}

func (c *DbIdSourceWrapper) PropertiesQuery() string {
	return c.p.GetUserPropertiesQueryString()
}

func (c *DbIdSourceWrapper) UpdateCredentials() string {
	return c.p.GetResetCredentialDml()
}

func (c *DbIdSourceWrapper) RelayCredentialQuery() string {
	return c.p.GetRelayCredentialQueryString()
}

// extension
//func (c *DbIdSourceWrapper) Definition() string {
//	return c.p.GetDefinition()
//}