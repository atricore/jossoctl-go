package formatter

import (
	"strconv"

	api "github.com/atricore/josso-api-go"
)

const (
	ldapTFFormat = `resource "iamtf_idsource_ldap" "{{.Name}}" {
	name = "{{.Name}}"
}`
	LdapPrettyFormat = `
 Directory Identity Source (built-in)
     
General:

    Name: {{.Name}} 
     ID:  {{.Id}}
    Documentation: {{.Description}}

  Connection:

   Initial context factory: {{.InitialCtxFactory}}
   Provider URL:            {{.ProviderUrl}}
   Principal:               {{.Principal}}
   Password:                {{.Password}}
   Authentication:          {{.Authentication}}
   Enable password update:  {{.EnablePasswordUpdate}}

  Lookup:

   User properties query:          {{.UserProperty}}
   Include operational attributes: {{.IncludeOperationalAttributes}}
   Updatable credential:           {{.UpdatableCredential}}
   Credentials query:              {{.CredentialsQuery}}
   Role identifier:                {{.RoleIdentifies}}
   Referrals:                      {{.Referrals}}
   Search scope:                   {{.SearchScope}}
   Role DN:                        {{.RoleDn}}
   Role matching mode:             {{.RoleMatchingMode}}
   User identifier:                {{.UserIdentifier}}
   User DN:                        {{.UserDn}}
` + extensionFormat
)

type idSourceLdapWrapper struct {
	HeaderContext
	trunc bool
	p     *api.LdapIdentitySourceDTO
}

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewLdapFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultIdSourceTableFormat
		}
	case TFFormatKey:
		return ldapTFFormat
	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return LdapPrettyFormat
		}
	case RawFormatKey:
		switch {
		case quiet:
			return `nameabc: {{.Name}}`
		default:
			return `nameavc: {{.Name}}
type: {{.Type}}
`
		}
	}

	format := Format(source)
	return format
}

func LdapWrite(ctx IdSourceContext, idsourcedb []api.LdapIdentitySourceDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return LdapFormat(ctx, idsourcedb, format)
	}
	return ctx.Write(newLdapWrapper(), render)

}

func LdapFormat(ctx IdSourceContext, idSourceLdaps []api.LdapIdentitySourceDTO, format func(subContext SubContext) error) error {
	for _, idSourceLdap := range idSourceLdaps {
		c := idSourceLdapWrapper{
			p:     &idSourceLdap,
			trunc: false,
		}
		if err := format(&c); err != nil {
			return err
		}
	}
	return nil
}

func newLdapWrapper() *idSourceLdapWrapper {
	LdapWrapper := idSourceLdapWrapper{}
	LdapWrapper.Header = SubHeaderContext{
		"Name": nameHeader,
		"Type": typeHeader,
	}
	return &LdapWrapper
}

func (c *idSourceLdapWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *idSourceLdapWrapper) ID() string {

	id := strconv.FormatInt(c.p.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

// General
func (c *idSourceLdapWrapper) Name() string {
	return c.p.GetName()
}

func (c *idSourceLdapWrapper) Id() int64 {
	return c.p.GetId()
}

func (c *idSourceLdapWrapper) Description() string {
	return c.p.GetDescription()
}

// connector

func (c *idSourceLdapWrapper) InitialCtxFactory() string {
	return c.p.GetInitialContextFactory()
}

func (c *idSourceLdapWrapper) ProviderUrl() string {
	return c.p.GetProviderUrl()
}

func (c *idSourceLdapWrapper) Principal() string {
	return c.p.GetPrincipalUidAttributeID()
}

func (c *idSourceLdapWrapper) Password() string {
	return c.p.GetSecurityCredential()
}

func (c *idSourceLdapWrapper) Authentication() string {
	return c.p.GetSecurityAuthentication()
}

func (c *idSourceLdapWrapper) EnablePasswordUpdate() bool {
	return c.p.GetUpdatePasswordEnabled()
}

//lookup
func (c *idSourceLdapWrapper) UserProperty() string {
	return c.p.GetUserPropertiesQueryString()
}

func (c *idSourceLdapWrapper) IncludeOperationalAttributes() bool {
	return c.p.GetIncludeOperationalAttributes()
}

func (c *idSourceLdapWrapper) UpdatableCredential() string {
	return c.p.GetUpdateableCredentialAttribute()
}

func (c *idSourceLdapWrapper) CredentialsQuery() string {
	return c.p.GetCredentialQueryString()
}

func (c *idSourceLdapWrapper) RoleIdentifies() string {
	return c.p.GetUidAttributeID()
}

func (c *idSourceLdapWrapper) Referrals() string {
	return c.p.GetReferrals()
}

func (c *idSourceLdapWrapper) SearchScope() string {
	return c.p.GetLdapSearchScope()
}

func (c *idSourceLdapWrapper) RoleDn() string {
	return c.p.GetRolesCtxDN()
}

func (c *idSourceLdapWrapper) RoleMatchingMode() string {
	return c.p.GetRoleMatchingMode()
}

func (c *idSourceLdapWrapper) UserIdentifier() string {
	return c.p.GetPrincipalUidAttributeID()
}

func (c *idSourceLdapWrapper) UserDn() string {
	return c.p.GetUsersCtxDN()
}

func (c *idSourceLdapWrapper) Extension() *CustomClassWrapper {
	return &CustomClassWrapper{cc: c.p.CustomClass}
}
