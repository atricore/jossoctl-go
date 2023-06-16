package formatter

import (
	"fmt"

	api "github.com/atricore/josso-api-go"
)

type asWrapper struct {
	as *api.AuthenticationMechanismDTO
}

func (c *asWrapper) Extension() *CustomClassWrapper {
	var w CustomClassWrapper

	if c.IsDirectoryAuthn() {
		directoryAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToDirectoryAuthnSvc()
		if err != nil {
			// TODO : error handling
			return &w
		}

		w.cc = directoryAuthn.CustomClass
	} // TODO : add other authn types that have extension

	return &w
}

func (c *asWrapper) Name() string {
	return c.as.GetName()
}

func (c *asWrapper) Priority() int32 {
	return c.as.GetPriority()
}

func (c *asWrapper) Class() string {
	return api.AsString(c.as.AdditionalProperties["@c"], "")

}

func (c *asWrapper) IsBasicAuthn() bool {
	if c.as.DelegatedAuthentication == nil {
		_, err := c.as.ToBasicAuthn()
		return err == nil
	}

	return false
}

func (c *asWrapper) PasswordHash() string {
	authn, err := c.as.ToBasicAuthn()
	if err != nil {
		return err.Error()
	}
	return authn.GetHashAlgorithm()
}

func (c *asWrapper) PasswordEncoding() string {
	authn, err := c.as.ToBasicAuthn()
	if err != nil {
		return err.Error()
	}
	return authn.GetHashEncoding()
}

func (c *asWrapper) SaltSuffix() string {
	authn, err := c.as.ToBasicAuthn()
	if err != nil {
		return err.Error()
	}
	return authn.GetSaltSuffix()
}

func (c *asWrapper) SaltPrefix() string {
	authn, err := c.as.ToBasicAuthn()
	if err != nil {
		return err.Error()
	}
	return authn.GetSaltPrefix()
}

func (c *asWrapper) SaltLength() string {
	authn, err := c.as.ToBasicAuthn()
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("%d", authn.GetSaltLength())
}

func (c *asWrapper) SAMLAuthnCtx() string {
	authn, err := c.as.ToBasicAuthn()
	if err != nil {
		return err.Error()
	}
	return authn.GetSimpleAuthnSaml2AuthnCtxClass()
}

func (c *asWrapper) IsDirectoryAuthn() bool {
	if c.as.DelegatedAuthentication == nil || c.as.DelegatedAuthentication.AuthnService == nil {
		// TODO : Improve error handling
		return false
	}

	return c.as.DelegatedAuthentication.AuthnService.IsDirectoryAuthnSvs()
}

func (c *asWrapper) InitialCtxFactory() string {
	directoryAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToDirectoryAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return directoryAuthn.GetInitialContextFactory()
}

func (c *asWrapper) ProviderUrl() string {
	directoryAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToDirectoryAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return directoryAuthn.GetProviderUrl()
}

func (c *asWrapper) Username() string {
	directoryAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToDirectoryAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return directoryAuthn.GetSecurityPrincipal()
}

func (c *asWrapper) Authentication() string {
	directoryAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToDirectoryAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return directoryAuthn.GetSecurityAuthentication()
}

func (c *asWrapper) PasswordPolicy() string {
	directoryAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToDirectoryAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return directoryAuthn.GetPasswordPolicy()
}

func (c *asWrapper) PerformDnSearch() bool {
	directoryAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToDirectoryAuthnSvc()
	if err != nil {
		return false
	}

	return directoryAuthn.GetPerformDnSearch()
}

func (c *asWrapper) UsersCtxDn() string {
	directoryAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToDirectoryAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return directoryAuthn.GetUsersCtxDN()
}

func (c *asWrapper) UserIdAttr() string {
	directoryAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToDirectoryAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return directoryAuthn.GetPrincipalUidAttributeID()
}

func (c *asWrapper) SamlAuthnCtx() string {
	directoryAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToDirectoryAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return directoryAuthn.GetSimpleAuthnSaml2AuthnCtxClass()
}

func (c *asWrapper) SearchScope() string {
	directoryAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToDirectoryAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return directoryAuthn.GetLdapSearchScope()
}

func (c *asWrapper) Referrals() string {
	directoryAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToDirectoryAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return directoryAuthn.GetReferrals()
}

func (c *asWrapper) OperationalAttrs() bool {
	directoryAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToDirectoryAuthnSvc()
	if err != nil {
		return false
	}

	return directoryAuthn.GetIncludeOperationalAttributes()
}

func (c *asWrapper) IsClientCertAuthn() bool {
	if c.as.DelegatedAuthentication == nil || c.as.DelegatedAuthentication.AuthnService == nil {
		// TODO : Improve error handling
		return false
	}

	return c.as.DelegatedAuthentication.AuthnService.IsClientCertAuthnSvs()
}

func (c *asWrapper) CrlRefreshSeconds() int32 {
	clientCertAuthn, _ := c.as.DelegatedAuthentication.AuthnService.ToClientCertAuthnSvc()

	return clientCertAuthn.GetCrlRefreshSeconds()
}

func (c *asWrapper) CrlUrl() string {
	clientCertAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToClientCertAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return clientCertAuthn.GetCrlUrl()
}

func (c *asWrapper) OcspEnabled() bool {
	clientCertAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToClientCertAuthnSvc()
	if err != nil {
		return false
	}

	return clientCertAuthn.GetOcspEnabled()
}

func (c *asWrapper) OcspServer() string {
	clientCertAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToClientCertAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return clientCertAuthn.GetOcspServer()
}

func (c *asWrapper) Ocspserver() string {
	clientCertAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToClientCertAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return clientCertAuthn.GetOcspserver()
}

func (c *asWrapper) Uid() string {
	clientCertAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToClientCertAuthnSvc()
	if err != nil {
		return err.Error()
	}

	return clientCertAuthn.GetUid()
}

func (c *asWrapper) IsOauth2PreAuthn() bool {
	if c.as.DelegatedAuthentication == nil || c.as.DelegatedAuthentication.AuthnService == nil {
		// TODO : Improve error handling
		return false
	}

	return c.as.DelegatedAuthentication.AuthnService.IsOauth2PreAuthnSvc()
}

func (c *asWrapper) AuthnService() string {
	oauth2PreAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToOauth2PreAuthnSvs()
	if err != nil {
		return err.Error()
	}

	return oauth2PreAuthn.GetAuthnService()
}

func (c *asWrapper) ExternalAuth() bool {
	oauth2PreAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToOauth2PreAuthnSvs()
	if err != nil {
		return false
	}

	return *oauth2PreAuthn.ExternalAuth
}

func (c *asWrapper) RememberMe() bool {
	oauth2PreAuthn, err := c.as.DelegatedAuthentication.AuthnService.ToOauth2PreAuthnSvs()
	if err != nil {
		return false
	}

	return oauth2PreAuthn.GetRememberMe()
}

// windows Integrated Authentication
func (c *asWrapper) IsWindowsAuthn() bool {
	if c.as.DelegatedAuthentication == nil || c.as.DelegatedAuthentication.AuthnService == nil {
		// TODO : Improve error handling
		return false
	}

	return c.as.DelegatedAuthentication.AuthnService.IsWindowsIntegratedAuthn()
}

// windows Integrated Authentication fields
func (c *asWrapper) Domain() string {
	wia, err := c.as.DelegatedAuthentication.AuthnService.ToWindowsIntegratedAuthn()
	if err != nil {
		return err.Error()
	}

	return wia.GetDomain()
}

func (c *asWrapper) DomainController() string {
	wia, err := c.as.DelegatedAuthentication.AuthnService.ToWindowsIntegratedAuthn()
	if err != nil {
		return err.Error()
	}

	return wia.GetDomainController()
}

func (c *asWrapper) Host() string {
	wia, err := c.as.DelegatedAuthentication.AuthnService.ToWindowsIntegratedAuthn()
	if err != nil {
		return err.Error()
	}

	return wia.GetHost()
}

func (c *asWrapper) OverwriteKerberosSetup() bool {
	wia, err := c.as.DelegatedAuthentication.AuthnService.ToWindowsIntegratedAuthn()
	if err != nil {
		return false
	}

	return wia.GetOverwriteKerberosSetup()
}

func (c *asWrapper) Port() int32 {
	wia, _ := c.as.DelegatedAuthentication.AuthnService.ToWindowsIntegratedAuthn()

	return wia.GetPort()
}

func (c *asWrapper) Protocol() string {
	wia, err := c.as.DelegatedAuthentication.AuthnService.ToWindowsIntegratedAuthn()
	if err != nil {
		return err.Error()
	}

	return wia.GetProtocol()
}

func (c *asWrapper) ServiceClass() string {
	wia, err := c.as.DelegatedAuthentication.AuthnService.ToWindowsIntegratedAuthn()
	if err != nil {
		return err.Error()
	}

	return wia.GetServiceClass()
}

func (c *asWrapper) ServiceName() string {
	wia, err := c.as.DelegatedAuthentication.AuthnService.ToWindowsIntegratedAuthn()
	if err != nil {
		return err.Error()
	}

	return wia.GetServiceName()
}

func (c *asWrapper) Keytab() string {
	wia, err := c.as.DelegatedAuthentication.AuthnService.ToWindowsIntegratedAuthn()
	if err != nil {
		return err.Error()
	}

	return wia.KeyTab.GetValue()
}

func (c *asWrapper) IsCustomAuthn() bool {
	return false
}
