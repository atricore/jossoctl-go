package formatter

import (
	"strconv"

	api "github.com/atricore/josso-api-go"
)

const (
	LdapPrettyFormat = `
	Directory Identity Source (built-in)
    	
General:

        Name:	{{.Name}} 
		ID:		{{.Id}}
        Documentation:	{{.Description}}

		Connection:

			Initial context factory:	{{.InitialCtxFactory}}
			Provider URL:	{{.ProviderUrl}}
			Principal:	{{.Principal}}
			Password:	{{.Password}}
			Authentication:	{{.Authentication}}
			Enable password update:	{{.EnablePasswordUpdate}}

		Lookup:

			User properties query:	{{.UserProperty}}
			Include operational attributes:	{{.IncludeOperationalAttributes}}
			Updatable credential:	{{.UpdatableCredential}}
			Credentials query:	{{.CredentialsQuery}}
			Role identifier:
			Referrls:	{{.Referrals}}
			Search scope:	{{.SearchScope}}
			Role DN:	{{.RoleDn}}
			Role user identifier attribute:
			Role matching mode:	{{.RoleMatchingMode}}
			User identifier:
			User DN:	{{.UserDn}}
	
		Extension:
	
			Definition:


`
)

type LdapWrapper struct {
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

func LdapFormat(ctx IdSourceContext, idsourceLdap []api.LdapIdentitySourceDTO, format func(subContext SubContext) error) error {
	for _, idsourceLdap := range idsourceLdap {
		var formatted []SubContext
		formatted = []SubContext{}
		c := LdapWrapper{
			p: &idsourceLdap,
		}
		formatted = append(formatted, &c)

		for _, idsourceLdapCtx := range formatted {
			if err := format(idsourceLdapCtx); err != nil {
				return err
			}
		}
	}
	return nil
}

func newLdapWrapper() *LdapWrapper {
	LdapWrapper := LdapWrapper{}
	LdapWrapper.Header = SubHeaderContext{
		"Name": nameHeader,
		"Type": typeHeader,
	}
	return &LdapWrapper
}

func (c *LdapWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *LdapWrapper) ID() string {

	id := strconv.FormatInt(c.p.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

// General
func (c *LdapWrapper) Name() string {
	return c.p.GetName()
}

func (c *LdapWrapper) Id() int64 {
	return c.p.GetId()
}

func (c *LdapWrapper) Description() string {
	return c.p.GetDescription()
}

// connector

func (c *LdapWrapper) InitialCtxFactory() string {
	return c.p.GetInitialContextFactory()
}

func (c *LdapWrapper) ProviderUrl() string {
	return c.p.GetProviderUrl()
}

func (c *LdapWrapper) Principal() string {
	return c.p.GetPrincipalUidAttributeID()
}

func (c *LdapWrapper) Password() string {
	return c.p.GetSecurityCredential()
}

func (c *LdapWrapper) Authentication() string {
	return c.p.GetSecurityAuthentication()
}

func (c *LdapWrapper) EnablePasswordUpdate() bool {
	return c.p.GetUpdatePasswordEnabled()
}

//lookup
func (c *LdapWrapper) UserProperty() string {
	return c.p.GetUserPropertiesQueryString()
}

func (c *LdapWrapper) IncludeOperationalAttributes() bool {
	return c.p.GetIncludeOperationalAttributes()
}

func (c *LdapWrapper) UpdatableCredential() string {
	return c.p.GetUpdateableCredentialAttribute()
}

func (c *LdapWrapper) CredentialsQuery() string {
	return c.p.GetCredentialQueryString()
}

// func (c *LdapWrapper) RoleIdentifies() string {
// 	return c.p.Get
// }

func (c *LdapWrapper) Referrals() string {
	return c.p.GetReferrals()
}

func (c *LdapWrapper) SearchScope() string {
	return c.p.GetLdapSearchScope()
}

func (c *LdapWrapper) RoleDn() string {
	return c.p.GetRolesCtxDN()
}

// func (c *LdapWrapper) RoleUserIdentifier() string {
// 	return c.p.()
// }

func (c *LdapWrapper) RoleMatchingMode() string {
	return c.p.GetRoleMatchingMode()
}

// func (c *LdapWrapper) UserIdentifier() string {
// 	return c.p.Get()
// }

func (c *LdapWrapper) UserDn() string {
	return c.p.GetUsersCtxDN()
}

// extension
// func (c *LdapWrapper) Definition() string {
// 	return c.p.()
// }
