package formatter

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	api "github.com/atricore/josso-api-go"
	util "github.com/atricore/josso-cli-go/util"
	cli "github.com/atricore/josso-sdk-go"
	"golang.org/x/crypto/pkcs12"
)

type idPWrapper struct {
	HeaderContext
	trunc   bool
	IdaName string
	p       *api.IdentityProviderDTO
}

const (
	idpTFFormat = `resource "iamtf_idp" "{{.Name}}" {
	ida                       = "{{.ApplianceName}}"
	name                      = "{{.Name}}"
	description               = "{{.Description}}"
 
	branding                  = "{{.Branding}}"
 
	dashboard_url             = "{{.DashboardURL}}"
	error_binding             = "{{.ErrorBinding}}"
	session_timeout           = {{.SessionTimeout}}
	max_sessions_per_user     = {{.MaxSessionPerUser}}
	destroy_previous_session  = {{.DestroyPreviousSession}}

` + idpSaml2TFFormat + `

	{{- if .OverrideChannel }}
	{{- range $sp := .SPs }}
	sp {
		name: "{{ $sp.Name }}"
		` + idpSaml2TFFormat + `
	}
	{{- end }}
	{{- end}}

	oauth2 {
		enabled                   = {{.OAuth2Enabled }}
		{{- if .OAuth2Enabled }}
		shared_key                = "{{.OAuth2SharedKey}}"
		token_validity            = {{.OAuth2TokenValidity}}
		rememberme_token_validity = {{.OAuth2RememberMeTokenValidity}}

		pwdless_authn_enabled     = {{.PwdlessAuthnEnabled}}

		{{- if .PwdlessAuthnEnabled}}
		pwdless_authn_subject     = "{{.PwdlessAuthnSubject}}"
		pwdless_authn_template    = "{{.PwdlessAuthnTemplate}}"
		pwdless_authn_to          = "{{.PwdlessAuthnTo}}"
		pwdless_authn_from        = "{{.PwdlessAuthnFrom}}"
		{{- end }}{{- end }}
	}

	oidc {
		enabled                     = {{.OIDCEnabled }}
		access_token_ttl		    = {{.OIDCAccessTokenTTL}}
		authz_code_ttl			    = {{.OIDCAuthzCodeTTL}}
		id_token_ttl			    = {{.OIDCIDTokenTTL}}
		user_claims_in_access_token = {{.OIDCUserClaimsInAccessToken}}

	}

` + keystoreTFFormat + `

}`

	idpSaml2TFFormat = `	saml2 {
		want_authn_req_signed        = {{.WantAuthnSigned}}
		want_req_signed              = {{.WantReqSigned}}
		sign_reqs                    = {{.SignReq}}
		signature_hash               = "{{.SignatureHash}}"
		encrypt_algorithm            = "{{.EncryptAlgorithm}}"
		bindings {
			http_post                = {{.HttpPostBinding}}
			http_redirect            = {{.HttpRedirectBinding}}
			artifact                 = {{.ArtifactBinding}}
			soap                     = {{.SoapBinding}}
			local                    = {{.LocalBinding}}
		}

		message_ttl                  = {{.MessageTTL}}
		message_ttl_tolerance        = {{.MessageTTLTolerance}}

	}`

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
        Class:                       {{$as.Class}} {{- if $as.IsBasicAuthn }}
            Password hash:           {{$as.PasswordHash}}   
            Password encoding:       {{$as.PasswordEncoding}}   
            Salt prefix:             {{$as.SaltPrefix}}   
            Salt suffix:             {{$as.SaltSuffix}}   
            SAML authn ctx:          {{$as.SAMLAuthnCtx}}   
            CRYPT salt length:       {{$as.SaltLength}}
        {{ end }} {{- if $as.IsDirectoryAuthn }}
        Directory Authentication Service
            Initial ctx factory:     {{$as.InitialCtxFactory}}
            Provider url:            {{$as.ProviderUrl}}
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
            CrlRefreshSeconds:       {{$as.CrlRefreshSeconds}}
            CrlUrl:                  {{$as.CrlUrl}}
            OcspServer:              {{$as.OcspServer}}
            Uid:                     {{$as.Uid}}
        {{ end }} {{- if $as.IsWindowsAuthn }}
        Windows    Integrated    Authentication
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
            AuthnService:            {{$as.AuthnService}}
            ExternalAuth:            {{$as.ExternalAuth}}
            RememberMe:              {{$as.RememberMe}} 
		{{ end }} {{ end }} 
    User Interface 
        Branding:                    {{.Branding}}
        ErrorBinding:                {{.ErrorBinding}}
        DashboardUrl:                {{.DashboardUrl}}
 
    SAML 2 
        Metadata Svc:                {{.Metadata}}
        Bindings:                    {{.Bindings}}
        Want AuthnReq Signed:        {{.WantAuthnSigned}}
        Sign Request:                {{.SignReq}}
        Encrypt Assertion:           {{.EncryptAssertion}}
        Encryption Algorithm:        {{.EncryptAlgorithm}}
        Signature Hash:              {{.SignatureHash}}
        Message TTL:                 {{.MessageTTL}}
        External Msg TTL Tolerance:  {{.MessageTTLTolerance}}
 
    Open ID Connect 
        Enabled:                     {{.EnabledOpenIdConnect}}
        Id token TTL (secs):         {{.IdTokenTTL}}
        Access token TTL (secs):     {{.AccessTokenTTL}}
        Authn code TTL (secs):       {{.AuthnCodeTTL}}
        User claims in access token: {{.UserClaimsInAccessToken}}
    
	OAuth2
        Enabled:    {{.OAuth2Enabled}}
        
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
            Bindings:                    {{$fc.Bindings}}
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
	case TFFormatKey:
		return idpTFFormat
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
			c := idPWrapper{IdaName: ctx.IdaName, p: &provider}
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
func (c *idPWrapper) ApplianceName() string {
	return c.IdaName
}

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

func (c *idPWrapper) DashboardURL() string {
	return c.p.GetDashboardUrl()
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

func (c *idPWrapper) Bindings() string {
	// concatenate c.p.GetActiveBindings() as a single string
	return strings.Join(c.p.GetActiveBindings(), ", ")
}

func (c *idPWrapper) HttpPostBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_HTTP_POST")
}

func (c *idPWrapper) HttpRedirectBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_HTTP_REDIRECT")
}

func (c *idPWrapper) SoapBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_SOAP")
}

func (c *idPWrapper) ArtifactBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_ARTIFACT")
}

func (c *idPWrapper) LocalBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_LOCAL")
}

func (c *idPWrapper) HasBinding(b string) bool {
	for _, binding := range c.p.GetActiveBindings() {
		if binding == b {
			return true
		}
	}
	return false
}

func (c *idPWrapper) Metadata() string {
	return c.Location() + "/SAML2/MD"
}

func (c *idPWrapper) WantAuthnSigned() bool {
	return c.p.GetWantAuthnRequestsSigned()
}

func (c *idPWrapper) WantReqSigned() bool {
	return c.p.GetWantSignedRequests()
}

func (c *idPWrapper) SignReq() bool {
	return c.p.GetSignRequests()
}

func (c *idPWrapper) EncryptAssertion() bool {
	return c.p.GetEncryptAssertion()
}

func (c *idPWrapper) EncryptAlgorithm() string {
	return c.p.GetEncryptAssertionAlgorithm()
}

func (c *idPWrapper) SignatureHash() string {
	h := c.p.GetSignatureHash()
	if h == "" {
		return "SHA256"
	}
	return h
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

func (c *idPWrapper) UserClaimsInAccessToken() bool {
	return c.p.GetOidcIncludeUserClaimsInAccessToken()
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

func (c *idPWrapper) OverrideChannel() bool {

	fmt.Printf("OverrideChannel: %v\n", c.p.GetFederatedConnectionsA())
	for _, fc := range c.p.GetFederatedConnectionsA() {
		if fc.ChannelA.GetOverrideProviderSetup() {
			return true
		}
	}
	return false

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

func (c *idPWrapper) HasKeystore() bool {
	cfg := c.p.GetConfig()
	idpCfg, _ := cfg.ToSamlR2IDPConfig()
	return !idpCfg.GetUseSampleStore() && !idpCfg.GetUseSystemStore()
}

func (c *idPWrapper) KeystoreResource() string {
	cfg := c.p.GetConfig()
	idpCfg, _ := cfg.ToSamlR2IDPConfig()
	return *idpCfg.GetSigner().Store.Value
}

func (c *idPWrapper) KeystorePassword() string {
	cfg := c.p.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return err.Error()
	}

	singer := idpCfg.GetSigner()

	return singer.GetPassword()

}

func (c *idPWrapper) HasKeyPassword() bool {
	cfg := c.p.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return false
	}

	singer := idpCfg.GetSigner()

	return singer.GetPrivateKeyPassword() != ""
}

func (c *idPWrapper) KeyPassword() string {
	cfg := c.p.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return err.Error()
	}

	singer := idpCfg.GetSigner()

	return singer.GetPrivateKeyPassword()
}

func (c *idPWrapper) HasCertificateAlias() bool {
	cfg := c.p.GetConfig()
	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return false
	}

	singer := idpCfg.GetSigner()
	return singer.GetCertificateAlias() != ""

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

func (c *idPWrapper) FederatedConnections() []IdPFcWrapper {
	// create an empty array of idpFcWrapper to hold the results
	ws := make([]IdPFcWrapper, len(c.p.GetFederatedConnectionsA()))
	for i := range c.p.GetFederatedConnectionsA() {
		// Do NOT use FC
		ws[i] = IdPFcWrapper{idx: i, Fc: &c.p.GetFederatedConnectionsA()[i]}
	}
	return ws
}

func (c *idPWrapper) Authns() []asWrapper {
	var asWrappers []asWrapper
	for i := range c.p.AuthenticationMechanisms {
		asWrappers = append(asWrappers, asWrapper{as: &c.p.AuthenticationMechanisms[i]})
	}
	return asWrappers
}
