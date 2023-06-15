package formatter

import (
	"fmt"
	"strconv"

	api "github.com/atricore/josso-api-go"
	cli "github.com/atricore/josso-sdk-go"
)

const (
	idSourceDBTFFormat = `resource "iamtf_idsource_db" "{{.Name}}" {
	ida = "{{.ApplianceName}}"
	name = "{{.Name}}"
}`
	idSourceDBPrettyFormat = `
DB Identity Source (built-in)
 
General:

  Name: {{.Name}}
  ID:  {{.Id}}
        Documentation: {{.Description}}

  Connectors

   JDBC Driver:     {{.JdbcDriver}}
   ConnectionUrl:   {{.ConnectionUrl}}
   Username:        {{.Username}}
   Password:        {{.Password}}

   Connection pooling:
   Acquire increment:  {{.AcquireIncrement}}
   Initial pool size:  {{.InitialPool}}
   Min size:           {{.MinSize}}
   Max size:           {{.MaxSize}}
   Idle test period:   {{.IdleConnectionTestPeriod}}
   Mx Idle time :      {{.MaxIdleTime}}

  Lookup
   Username query:                 {{.UsernameQuery}}
   Roles query:                    {{.RolesQuery}}
   Credentials query:              {{.CredentialsQuery}}
   Use result columns as property: {{.UseColumnNamesAsPropertyNames}}
   Properties query:               {{.PropertiesQuery}}
   Update credentials query:       {{.UpdateCredentials}}
   Relay credentials query:        {{.RelayCredentialQuery}}
 ` + extensionFormat
)

type DbIdSourceWrapper struct {
	HeaderContext
	trunc   bool
	idaName string
	p       *api.DbIdentitySourceDTO
}
type CustomClassProp struct {
	props *api.CustomClassPropertyDTO
}

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewDbIdSouceFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultIdSourceTableFormat
		}
	case TFFormatKey:
		return idSourceDBTFFormat
	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return idSourceDBPrettyFormat
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

func IdSourceDBWrite(ctx IdSourceContext, idsourcedb []api.DbIdentitySourceDTO) error {
	fmt.Println("db write")
	render := func(format func(subContext SubContext) error) error {
		return IdSourceFormat(ctx, idsourcedb, format)
	}
	return ctx.Write(newIdSourceDBWrapper(), render)

}

func IdSourceFormat(ctx IdSourceContext, idsources []api.DbIdentitySourceDTO, format func(subContext SubContext) error) error {
	for _, idsource := range idsources {
		var formatted []SubContext
		formatted = []SubContext{}
		c := DbIdSourceWrapper{
			idaName: ctx.IdaName,
			p:       &idsource,
		}
		formatted = append(formatted, &c)

		for _, idsourceCtx := range formatted {
			if err := format(idsourceCtx); err != nil {
				return err
			}
		}
	}
	return nil
}

func newIdSourceDBWrapper() *DbIdSourceWrapper {
	DbIdSourceWrapper := DbIdSourceWrapper{}
	DbIdSourceWrapper.Header = SubHeaderContext{
		"Name": nameHeader,
		"Type": typeHeader,
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
func (c *DbIdSourceWrapper) ApplianceName() string {
	return c.idaName
}

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
	return c.p.GetDriverName()
}

func (c *DbIdSourceWrapper) ConnectionUrl() string {
	return c.p.GetConnectionUrl()
}

func (c *DbIdSourceWrapper) Username() string {
	return c.p.GetAdmin()
}

func (c *DbIdSourceWrapper) Password() string {
	return c.p.GetPassword()
}

func (c *DbIdSourceWrapper) ConnectionPooling() bool {
	return c.p.GetPooledDatasource()
}

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

// TODO : Add Extension to wrapper
