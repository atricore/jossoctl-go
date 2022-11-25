package formatter

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strconv"

	api "github.com/atricore/josso-api-go"
	util "github.com/atricore/josso-cli-go/util"
	cli "github.com/atricore/josso-sdk-go"
	"golang.org/x/crypto/pkcs12"
)

type idPWrapper struct {
	HeaderContext
	trunc bool
	p     *api.IdentityProviderDTO
}

type idpFcWrapper struct {
	idx int
	fc  *api.FederatedConnectionDTO
}

type asWrapper struct {
	as *api.AuthenticationMechanismDTO
}
type amWrapper struct {
	am *api.AttributeMappingDTO
}

const (
	idpPrettyFormat = `
Identity Provider (built-in)
 

General

    Name:                            {{.Name}}
    Id:                              {{.Id}}
    Location:                        {{.Location}}
    Description                      {{.Description}}

    Session
        Session timeout:             {{.SessionTimeout}}
        Max session per user:        {{.MaxSessionPerUser}}
        Destroy previous session:    {{.DestroyPreviousSession}}
        Session manager:             {{.SessionManager}}

    User Identifier
        Type:                        {{.Type}}
        Attribute:                   {{.Attribute}}
        Ignore Requested UserIDType: {{.IgnoreRequestedUserIDType}}

    Authentication {{ range $as := .Authns }}
        Name:                        {{$as.Name}}
        Priority:                    {{$as.Priority}}
        Class:                       {{$as.Class}} {{- if $as.IsDirectoryAuthn }}
        Directory Authentication Service
            Priority:                {{$as.Priority}}
            InitialCtxFactory:       {{$as.InitialCtxFactory}}
            provider url:            {{$as.ProviderUrl}}
            Username:                {{$as.Username}}
            Authentication:          {{$as.Authentication}}
            PasswordPolicy:          {{$as.PasswordPolicy}}
            PerformDnSearch:         {{$as.PerformDnSearch}}
            UsersCtxDn:              {{$as.UsersCtxDn}}
            UserIdAttr:              {{$as.UserIdAttr}}
            SamlAuthnCtx:            {{$as.SamlAuthnCtx}}
            SearchScope:             {{$as.SearchScope}}
            Referrals:               {{$as.Referrals}}
            OperationalAttrs:        {{$as.OperationalAttrs}}
        {{ end }} {{- if $as.IsClientCertAuthn }}
        Client Cert Authentication 
            Priority:                {{$as.Priority}}
            CrlRefreshSeconds:       {{$as.CrlRefreshSeconds}}
            CrlUrl:                  {{$as.CrlUrl}}
            OcspServer:              {{$as.OcspServer}}
            Ocspserver:              {{$as.Ocspserver}}
            Uid:                     {{$as.Uid}}
        {{ end }} {{- if $as.IsWindowsAuthn }}
        Windows    Integrated    Authentication
            Priority:                {{$as.Priority}}
            Domain:                  {{$as.Domain}}
            DomainController:        {{$as.DomainController}}
            Host:                    {{$as.Host}}
            Overwrite Kerberos cfg:  {{$as.OverwriteKerberosSetup}}
            Protocol:                {{$as.Protocol}}
            ServiceClass:            {{$as.ServiceClass}}
            ServiceName:             {{$as.ServiceName}}
            Keytab:                  {{$as.Keytab}}
        {{ end }} {{- if $as.IsOauth2PreAuthn }}
        OAuth2 Pre Authentication Service
            Priority:                {{$as.Priority}}
            AuthnService:            {{$as.AuthnService}}
            ExternalAuth:            {{$as.ExternalAuth}}
            RememberMe:              {{$as.RememberMe}} 
		{{ end }} {{ end }} 
    User Interface 
        Branding:                    {{.Branding}}
        ErrorBinding:                {{.ErrorBinding}}
        DashboardUrl:                {{.DashboardUrl}}
 
    SAML 2 
        Metadata Svc:                {{.MetadataSvc}}
        Want AuthnReq Signed:        {{.WantAuthnSigned}}
        Sign Request:                {{.SignReq}}
        Encrypt Assertion:           {{.EncryptAssertion}}
        Encryption Algorithm:        {{.EncrptionAlgorithm}}
        Signature Hash:              {{.SignatureHash}}
        Message TTL:                 {{.MessageTTL}}
        External Msg TTL Tolerance:  {{.MessageTTLTolerance}}
 
    Open ID Connect 
        Enabled:                     {{.EnabledOpenIdConnect}}
        Id token TTL (secs):         {{.IdTokenTTL}}
        Access token TTL (secs):     {{.AccessTokenTTL}}
        Authn code TTL (secs):       {{.AuthnCodeTTL}}
    
	OAuth2
        Enabled:    {{.EnabledOauth2}}
        
    Claims/Attributes
        Profile:                     {{.Profile}}
        Profile Type:                {{.ProfileType}} {{ range $am := .AttributeMapping }} {{- if .IsCustomClass}}
            Attribute:               {{$am.AttrName}}
		    Mapping type:            {{$am.Type}}
            Mapping expression:      {{$am.ReportedAttrName}}
            Reported Format:         {{$am.ReportedAttrNameFormat}}
        {{ end     }}    
        {{ end     }}
        
    Federated connections {{ range $fc := .FederatedConnections }}
        SP Channel:                  {{$fc.ChannelName}}
        Target Provider:             {{$fc.ConnectionName}}		
        Override Provider:           {{$fc.OverrideProvider}} {{- if $fc.OverrideProvider }}
        Location:                    {{$fc.Location}}
		
        SAML 2
            Metadata Svc:                {{$fc.Metadata}}
            Sing authn requests:         {{$fc.SignAuthenticationRequests}}
            Want assertion signed:       {{$fc.WantAssertionSigned}}
            Signature hash:              {{$fc.SignatureHash}}
            Message TTL:                 {{$fc.MessageTTL}}
            Message TTL Tolerance:       {{$fc.MessageTTLTolerance}}{{ end }}
            {{ end }}

` + keystoreFormat
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

	// Render is a function that receives a format function and writes its output to the proper output
	render := func(format func(subContext SubContext) error) error {

		for _, provider := range providers {
			c := idPWrapper{p: &provider}
			if err := format(&c); err != nil {
				return err
			}
		}
		return nil

	}

	return ctx.Write(newIdPWrapper(), render)

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

// General
func (c *idPWrapper) Name() string {
	return c.p.GetName()
}

func (c *idPWrapper) Id() int64 {
	return c.p.GetId()
}

func (c *idPWrapper) Location() string {
	return cli.LocationToStr(c.p.Location)
}

func (c *idPWrapper) Description() string {

	return c.p.GetDescription()
}

// Session
func (c *idPWrapper) SessionTimeout() int32 {
	return c.p.GetSsoSessionTimeout()
}

func (c *idPWrapper) MaxSessionPerUser() int32 {
	return c.p.GetMaxSessionsPerUser()

}

func (c *idPWrapper) DestroyPreviousSession() bool {
	return c.p.GetDestroyPreviousSession()
}

func (c *idPWrapper) SessionManager() string {
	return c.p.SessionManagerFactory.GetName()
}

//    User Identifier
func (c *idPWrapper) Type() string {
	return api.AsString(c.p.AdditionalProperties["@c"], "N/A")
}

func (c *idPWrapper) SingerValue() string {

	cfg := c.p.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return err.Error()
	}

	singer := idpCfg.GetSigner()
	value := singer.Store.GetValue()

	return value
}

func (c *idPWrapper) Attribute() string {
	ap := c.p.AttributeProfile.GetName()
	return ap

}

func (c *idPWrapper) IgnoreRequestedUserIDType() bool {
	return c.p.GetIgnoreRequestedNameIDPolicy()
}

// Authentication

//    User Interface
func (c *idPWrapper) Branding() string {
	return c.p.GetUserDashboardBranding()
}

func (c *idPWrapper) ErrorBinding() string {
	return c.p.GetErrorBinding()
}

func (c *idPWrapper) DashboardUrl() string {
	return c.p.GetDashboardUrl()
}

// SAML 2

func (c *idPWrapper) Profiles() int {
	return len(c.p.GetActiveProfiles())
}

func (c *idPWrapper) Bindings() int {
	return len(c.p.GetActiveBindings())
}

func (c *idPWrapper) WantAuthnSigned() bool {
	return c.p.GetWantAuthnRequestsSigned()
}

func (c *idPWrapper) SignReq() bool {
	return c.p.GetSignRequests()
}

func (c *idPWrapper) EncryptAssertion() bool {
	return c.p.GetEncryptAssertion()
}

func (c *idPWrapper) EncrptionAlgorithm() string {
	return c.p.GetEncryptAssertionAlgorithm()
}

func (c *idPWrapper) SignatureHash() string {
	return c.p.GetSignatureHash()
}

func (c *idPWrapper) MessageTTL() int32 {
	return c.p.GetMessageTtl()
}

func (c *idPWrapper) MessageTTLTolerance() int32 {
	return c.p.GetMessageTtlTolerance()
}

// Open ID Connect
func (c *idPWrapper) Enabled() bool {
	return c.p.GetOpenIdEnabled()
}

func (c *idPWrapper) IdTokenTTL() int32 {
	return c.p.GetOidcIdTokenTimeToLive()
}

func (c *idPWrapper) AccessTokenTTL() int32 {
	return c.p.GetOidcAccessTokenTimeToLive()
}

func (c *idPWrapper) AuthnCodeTTL() int32 {
	return c.p.GetOidcAuthzCodeTimeToLive()
}

// OAuth2
func (c *idPWrapper) EnabledOauth2() bool {
	return c.p.GetOauth2Enabled()
}

// OpenId Connect
func (c *idPWrapper) EnabledOpenIdConnect() bool {
	return c.p.GetOpenIdEnabled()
}

// Subjets Attrubutes

func (c *idPWrapper) Profile() string {
	atp := c.p.GetAttributeProfile()
	profile := atp.GetName()
	return profile
}

func (c *idPWrapper) ProfileType() string {
	atp := c.p.AttributeProfile
	profileT := atp.GetProfileType()
	return profileT
}

func (c *idPWrapper) IsCustomClass() bool {
	atp := c.p.GetAttributeProfile()
	pt := atp.GetProfileType()
	if pt != "CUSTOM" {
		return false
	} else {
		return true
	}
}

func (c *idPWrapper) AttributeMapping() []amWrapper {
	var amWrappers []amWrapper
	ap := c.p.AttributeProfile.ToAttributeMapperProfile()
	for i := range ap.GetAttributeMaps() {
		amWrappers = append(amWrappers, amWrapper{am: &ap.GetAttributeMaps()[i]})
	}
	return amWrappers
}

func (c *amWrapper) AttrName() string {
	return c.am.GetAttrName()
}

func (c *amWrapper) ReportedAttrName() string {
	return c.am.GetReportedAttrName()
}

func (c *amWrapper) ReportedAttrNameFormat() string {
	return c.am.GetReportedAttrNameFormat()
}

func (c *amWrapper) Type() string {
	return c.am.GetType()
}

// keystore
func DecodePkcs12(pkcs string, password string) (*x509.Certificate, *rsa.PrivateKey, error) {
	Decode, err := base64.StdEncoding.DecodeString(pkcs)
	if err != nil {
		return nil, nil, err
	}

	privateKey, certificate, err := pkcs12.Decode(Decode, password)
	if err != nil {
		return nil, nil, err
	}

	rsaPrivateKey, isRsaKey := privateKey.(*rsa.PrivateKey)
	if !isRsaKey {
		return nil, nil, fmt.Errorf("PKCS#12 certificate must contain an RSA private key")
	}

	return certificate, rsaPrivateKey, nil
}

func (c *idPWrapper) getCertificateForSinger() (cert *x509.Certificate, err error) {
	cfg := c.p.GetConfig()

	idpCfg, _ := cfg.ToSamlR2IDPConfig()

	singer := idpCfg.GetSigner()
	pass := singer.GetPassword()
	store := singer.GetStore()
	vl := store.GetValue()

	cert, _, err = DecodePkcs12(vl, pass)
	if err != nil {
		return nil, err
	}

	return cert, err
}

func (c *idPWrapper) getCertificateForEncrypter() (cert *x509.Certificate, err error) {
	cfg := c.p.GetConfig()
	idpCfg, _ := cfg.ToSamlR2IDPConfig()
	encypter := idpCfg.GetEncrypter()
	pass := encypter.GetPassword()
	store := encypter.GetStore()
	vl := store.GetValue()

	cert, _, err = DecodePkcs12(vl, pass)
	if err != nil {
		return nil, err
	}

	return cert, err
}

func (c *idPWrapper) CertificateAlias() string {
	cfg := c.p.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return err.Error()
	}

	singer := idpCfg.GetSigner()

	return singer.GetCertificateAlias()

}

func (c *idPWrapper) KeyAlias() string {
	cfg := c.p.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return err.Error()
	}

	encypter := idpCfg.GetEncrypter()

	aliaskey := encypter.GetPrivateKeyName()

	return aliaskey
}

func (c *idPWrapper) Certificate() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}
	certStr, err := util.CertificateToPEM(cert)
	return fmt.Sprint(certStr)

}

func (c *idPWrapper) Version() int {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return 0
	}

	return cert.Version
}

func (c *idPWrapper) SerialNumber() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	return cert.SerialNumber.String()
}

func (c *idPWrapper) Issuer() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	return cert.Issuer.String()
}

func (c *idPWrapper) Subjects() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	return cert.Subject.String()
}

func (c *idPWrapper) NotBefore() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}
	return cert.NotBefore.String()
}

func (c *idPWrapper) NotAfter() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	return cert.NotAfter.String()
}

func (c *idPWrapper) FederatedConnections() []idpFcWrapper {
	// create an empty array of idpFcWrapper to hold the results
	ws := make([]idpFcWrapper, len(c.p.GetFederatedConnectionsA()))
	for i := range c.p.GetFederatedConnectionsA() {
		// Do NOT use FC
		ws[i] = idpFcWrapper{idx: i, fc: &c.p.GetFederatedConnectionsA()[i]}
	}
	return ws
}

func (c *idpFcWrapper) ChannelName() string {
	return c.fc.ChannelA.GetName()
}

func (c *idpFcWrapper) Location() string {
	l := c.fc.ChannelA.GetLocation()
	return cli.LocationToStr(&l)
}

func (c *idpFcWrapper) Metadata() string {
	return c.Location() + "/SAML2/MD"
}

func (c *idpFcWrapper) ConnectionName() string {
	return c.fc.GetName()
}

func (c *idpFcWrapper) OverrideProvider() bool {

	return c.fc.ChannelA.GetOverrideProviderSetup()
}

func (c *idpFcWrapper) SignatureHash() string {
	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}

	return idpchannel.GetSignatureHash()
}

func (c *idpFcWrapper) MessageTTL() int32 {
	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return 1
	}
	return idpchannel.GetMessageTtl()
}

func (c *idpFcWrapper) MessageTTLTolerance() int32 {
	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return 1
	}
	return idpchannel.GetMessageTtlTolerance()
}

func (c *idpFcWrapper) AccountLinkagePolicy() string {
	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}
	return idpchannel.AccountLinkagePolicy.GetLinkEmitterType()
}

func (c *idpFcWrapper) EnableProxyExtension() bool {
	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return false
	}
	return idpchannel.GetEnableProxyExtension()
}

func (c *idpFcWrapper) IdentityMappingPolicy() string {
	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}
	return idpchannel.IdentityMappingPolicy.GetMappingType()
}

func (c *idpFcWrapper) SignAuthenticationRequests() bool {
	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return false
	}
	return idpchannel.GetSignAuthenticationRequests()
}

func (c *idpFcWrapper) WantAssertionSigned() bool {
	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return false
	}
	return idpchannel.GetWantAssertionSigned()
}

func (c *idPWrapper) Authns() []asWrapper {
	var asWrappers []asWrapper
	for i := range c.p.AuthenticationMechanisms {
		asWrappers = append(asWrappers, asWrapper{as: &c.p.AuthenticationMechanisms[i]})
	}
	return asWrappers
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

/*"authn_basic":

"pwd_hash":
"pwd_encoding":
"crypt_salt_lenght":s
"salt_prefix":
"salt_suffix":
"saml_authn_ctx"*/

func (c *asWrapper) IsDirectoryAuthn() bool {
	if c.as.DelegatedAuthentication == nil || c.as.DelegatedAuthentication.AuthnService == nil {
		// TODO : Improve errror handling
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
		// TODO : Improve errror handling
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
		// TODO : Improve errror handling
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
		// TODO : Improve errror handling
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
