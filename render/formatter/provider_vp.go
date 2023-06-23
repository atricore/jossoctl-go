package formatter

import (
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"

	api "github.com/atricore/josso-api-go"
	util "github.com/atricore/josso-cli-go/util"
	cli "github.com/atricore/josso-sdk-go"
)

type VpWrapper struct {
	HeaderContext
	trunc     bool
	IdaName   string
	Provider  *api.VirtualSaml2ServiceProviderDTO
	Container *api.ProviderContainerDTO
}

type VPFcWrapper struct {
	Preferred bool
	IdP       string
	Sp        string
	Fc        *api.FederatedConnectionDTO
}

const (
	vpTFFormat = `resource "iamtf_vp" "{{.Name}}" {
    ida                   = "{{.ApplianceName}}"
    name                  = "{{.Name}}"
    description           = "{{.DisplayName}}"

	{{- if .HasDashboardURL}}
    dashboard_url         = "{{.DashboardURL}}" 
	{{- end}}
    error_binding         = "{{.ErrorBinding}}"
    session_timeout       = "{{.SessionTimeout}}"

    saml2_sp {
        account_linkage       = "{{.Saml2AccountLinkage}}"
        identity_mapping      = "{{.Saml2IdentityMapping}}"
        sign_requests         = {{.SignReq}}
        sign_authentication_requests = {{.SingAuthnReq}}
		want_assertion_signed = {{.WantAssertionSigned}}
        bindings {
            http_post         = {{.HttpPostBinding}}
            http_redirect     = {{.HttpRedirectBinding}}
            artifact          = {{.ArtifactBinding}}
            soap              = {{.SoapBinding}}
            local             = {{.LocalBinding}}
        }
		signature_hash        = "{{.SpSignatureHash}}"
        message_ttl           = {{.MessageTTL}}
        message_ttl_tolerance = {{.MessageTTLTolerance}}
    }

    saml2_idp {
        want_authn_req_signed = {{.WantAuthnSigned}} 
        want_req_signed       = {{.WantReqSigned}}
        sign_reqs             = {{.SignReq}}
        signature_hash        = "{{.IdPSignatureHash}}"
        encrypt_algorithm     = "{{.EncryptAlgorithm}}"
        bindings {
            http_post         = {{.HttpPostBinding}}
            http_redirect     = {{.HttpRedirectBinding}}
            artifact          = {{.ArtifactBinding}}
            soap              = {{.SoapBinding}}
            local             = {{.LocalBinding}}
        }
        message_ttl           = {{.MessageTTL}}
        message_ttl_tolerance = {{.MessageTTLTolerance}}
    }

	{{ range $idp := .IdPs }}
    idp {
        name         = "{{ $idp.IdP }}"
        is_preferred = {{ $idp.IsPreferred }}
    }
	{{- end}}
	
	` + keystoreTFFormat + `
}`

	VpPrettyFormat = `
SAML Virtual Provider (built-in)    

General 
    Name:                               {{.Name}}
    Description :                       {{.DisplayName}}
    Location:                           {{.Location}}

Provider
    Dashboard URL:                      {{.DashboardURL}}
    Error Binding:                      {{.ErrorBinding}}    

    SAML2
        Bindings:                       {{.Bindings}}
        Message TTL:                    {{.MessageTTL}}
        External Msg TTL Tolerance:     {{.MessageTTLTolerance}}

Identity Provider Side
    Session
        Session timeout:                {{.SessionTimeout}}
        Session manager:                {{.SessionManager}}

    User Identifier
        Type:                           {{.SubjectAttrType}}
        Attribute:                      {{.SubjectAttrName}}
        Value:                          {{.SubjectAttrValue}}
        Ignore Requested UserIDType:    {{.IgnoreRequestedUserIDType}}
    
    SAML2    
        Metadata:                       {{.IdPMetadata}}
        Want AuthnReq Signed:           {{.WantAuthnSigned}}
        Sign Request:                   {{.SignReq}}
        Encrypt Assertion:              {{.EncryptAssertion}}
        Encryption Algorithm:           {{.EncryptAlgorithm}}
        Signature Hash:                 {{.IdPSignatureHash}}


    Federated connections {{ range $fc := .IdPFederatedConnections}}
        Target:                         {{$fc.ConnectionName}}{{- if $fc.OverrideProvider }} (Override SAML2)
            Location:                   {{$fc.Location}}            
            Metadata Svc:               {{$fc.Metadata}}
            Want AuthnReq Signed:       {{$fc.WantAuthnSigned}}
            Sign Request:               {{$fc.SignReq}}
            Encrypt Assertion:          {{$fc.EncryptAssertion}}
            Encryption Algorithm:       {{$fc.EncryptAlgorithm}}
            Signature Hash:             {{$fc.SignatureHash}}
		{{- end }}
	{{end }}

Service Provider Side

    Account linkage:                    {{.AccountLinkage}}	
    Identity mapping:                   {{.IdentityMapping}}

    SAML2    
        Metadata:                       {{.SpMetadata}}        
        Sing auth request:              {{.SingAuthnReq}}
        Want assertion signed:          {{.WantAssertionSigned}}
        Want request signed:            {{.WantRequestSigned}}
        Sign requests:                  {{.SignRequests}}
        Signature hash:                 TODO
        Message TTL:                    {{.MessageTTL}}
        External Msg TTL Tolerance:     {{.MessageTTLTolerance}}        

        
    Federated connections {{ range $fc := .SPFederatedConnections}}
        Target:                         {{$fc.ConnectionName}}{{- if $fc.IsPreferred}} (preferred){{- end}}
    	{{- if $fc.OverrideProvider }}
            Metadata:                   {{$fc.Metadata}}        
            Account linkage:            {{$fc.AccountLinkage}}
            Identity mapping:           {{$fc.IdentityMapping}}
            Bindings:                   {{$fc.Bindings}}
    	    Sing authn request:         {{$fc.SignAuthenticationRequests}}
    	    Want assertion Signed:      {{$fc.WantAssertionSigned}}
    	    Signature hash:             {{$fc.SignatureHash}}
    	    Message TTL:                {{$fc.MessageTTL}}
    	    External msg TTL tolerance: {{$fc.MessageTTLTolerance}}
    	    Enable proxy Extension:     {{$fc.EnableProxyExtension}}
    	{{- end }}
		{{- end }}

` + keystoreFormat
)

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewVpFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultProviderTableFormat
		}
	case TFFormatKey:
		return vpTFFormat
	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return VpPrettyFormat
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

func VpWrite(ctx ProviderContext, providers []VpWrapper) error {
	render := func(format func(subContext SubContext) error) error {
		return vpFormat(ctx, providers, format)
	}
	return ctx.Write(newVpWrapper(), render)

}

func vpFormat(ctx ProviderContext, providers []VpWrapper, format func(subContext SubContext) error) error {
	for _, provider := range providers {
		if err := format(&provider); err != nil {
			return err
		}
	}
	return nil
}

func newVpWrapper() *VpWrapper {
	VpWrapper := VpWrapper{}
	VpWrapper.Header = SubHeaderContext{
		"Name":     nameHeader,
		"Type":     typeHeader,
		"Location": locationHeader,
	}
	return &VpWrapper
}

func (c *VpWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

// General
func (c *VpWrapper) Name() string {
	return c.Provider.GetName()
}

func (c *VpWrapper) SpId() string {

	return *c.Provider.Name
}

func (c *VpWrapper) ApplianceName() string {
	return c.IdaName
}

func (c *VpWrapper) ID() string {

	id := strconv.FormatInt(c.Provider.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

func (c *VpWrapper) DisplayName() string {
	return c.Provider.GetDisplayName()
}

func (c *VpWrapper) Location() string {
	return cli.LocationToStr(c.Provider.Location)
}

func (c *VpWrapper) SessionTimeout() int32 {
	return c.Provider.GetSsoSessionTimeout()
}

func (c *VpWrapper) SessionManager() string {
	return c.Provider.SessionManagerFactory.GetName()
}

func (c *VpWrapper) Description() string {
	return c.Provider.GetDescription()
}

func (c *VpWrapper) SubjectAttrType() string {
	return *c.Provider.SubjectNameIDPolicy.Type
}

func (c *VpWrapper) SubjectAttrName() string {
	return *c.Provider.SubjectNameIDPolicy.Name
}

func (c *VpWrapper) SubjectAttrValue() string {
	return c.Provider.SubjectNameIDPolicy.GetSubjectAttribute()
}

func (c *VpWrapper) IgnoreRequestedUserIDType() bool {
	return c.Provider.GetIgnoreRequestedNameIDPolicy()
}

func (c *VpWrapper) AccountLinkage() string {
	return c.Provider.AccountLinkagePolicy.GetName()
}

func (c *VpWrapper) Saml2AccountLinkage() string {
	return c.Provider.AccountLinkagePolicy.GetLinkEmitterType()
}

func (c *VpWrapper) IdentityMapping() string {
	return c.Provider.IdentityMappingPolicy.GetName()
}

func (c *VpWrapper) Saml2IdentityMapping() string {
	return c.Provider.IdentityMappingPolicy.GetMappingType()
}

func (c *VpWrapper) DashboardURL() string {
	return c.Provider.GetDashboardUrl()
}

func (c *VpWrapper) HasDashboardURL() bool {
	return c.Provider.GetDashboardUrl() != ""
}

func (c *VpWrapper) ErrorBinding() string {
	return c.Provider.GetErrorBinding()
}

// SAML2 SP
func (c *VpWrapper) SpMetadata() string {
	// https://dev-sso.shrm.org/IDBUS/SHRM-DEV/VP-IDP-PROXY
	return fmt.Sprintf("%s-SP-PROXY/SAML2/MD", c.Location())
}

// SAML2 IPD
func (c *VpWrapper) IdPMetadata() string {
	// https://dev-sso.shrm.org/IDBUS/SHRM-DEV/VP-IDP-PROXY
	return fmt.Sprintf("%s-IDP-PROXY/SAML2/MD", c.Location())
}

func (c *VpWrapper) WantAuthnSigned() bool {
	return c.Provider.GetWantAuthnRequestsSigned()
}

func (c *VpWrapper) WantReqSigned() bool {
	return c.Provider.GetWantSignedRequests()
}

func (c *VpWrapper) SignReq() bool {
	return c.Provider.GetSignRequests()
}

func (c *VpWrapper) EncryptAssertion() bool {
	return c.Provider.GetEncryptAssertion()
}

func (c *VpWrapper) EncryptAlgorithm() string {
	return mapSaml2EncryptionToTF(c.Provider.GetEncryptAssertionAlgorithm())
}

func (c *VpWrapper) Bindings() string {
	// concatenate c.p.GetActiveBindings() as a single string
	return strings.Join(c.Provider.GetActiveBindings(), ", ")
}

func (c *VpWrapper) HttpPostBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_HTTP_POST")
}

func (c *VpWrapper) HttpRedirectBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_HTTP_REDIRECT")
}

func (c *VpWrapper) SoapBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_SOAP")
}

func (c *VpWrapper) ArtifactBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_ARTIFACT")
}

func (c *VpWrapper) LocalBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_LOCAL")
}

func (c *VpWrapper) HasBinding(b string) bool {
	for _, binding := range c.Provider.GetActiveBindings() {
		if binding == b {
			return true
		}
	}
	return false
}

func (c *VpWrapper) SingAuthnReq() bool {
	return c.Provider.GetSignAuthenticationRequests()
}

func (c *VpWrapper) WantAssertionSigned() bool {
	return c.Provider.GetWantAssertionSigned()
}

func (c *VpWrapper) WantRequestSigned() bool {
	return c.Provider.GetWantSignedRequests()
}

func (c *VpWrapper) SignRequests() bool {
	return c.Provider.GetSignRequests()
}

func (c *VpWrapper) MessageTTL() int32 {
	return c.Provider.GetMessageTtl()
}

func (c *VpWrapper) MessageTTLTolerance() int32 {
	return c.Provider.GetMessageTtlTolerance()
}

func (c *VpWrapper) Profiles() int {
	return len(c.Provider.GetActiveProfiles())
}

func (c *VpWrapper) SpSignatureHash() string {
	return mapSaml2SignatureToTF(c.Provider.GetSpSignatureHash())
}

func (c *VpWrapper) IdPSignatureHash() string {
	return mapSaml2SignatureToTF(c.Provider.GetIdpSignatureHash())
}

func (c *VpWrapper) SPFederatedConnections() []SPFcWrapper {
	var fcWrappers []SPFcWrapper
	for i := range c.Provider.FederatedConnectionsB {
		fcWrappers = append(fcWrappers, SPFcWrapper{Fc: &c.Provider.FederatedConnectionsB[i]})
	}
	return fcWrappers
}

func (c *VpWrapper) IdPFederatedConnections() []IdPFcWrapper {
	var fcWrappers []IdPFcWrapper
	for i := range c.Provider.FederatedConnectionsA {
		fcWrappers = append(fcWrappers, IdPFcWrapper{Fc: &c.Provider.FederatedConnectionsA[i]})
	}
	return fcWrappers
}

func (c *VpWrapper) HasKeystore() bool {
	cfg := c.Provider.GetConfig()
	idpCfg, _ := cfg.ToSamlR2IDPConfig()
	return !idpCfg.GetUseSampleStore() && !idpCfg.GetUseSystemStore()
}

func (c *VpWrapper) KeystoreResource() string {
	cfg := c.Provider.GetConfig()
	idpCfg, _ := cfg.ToSamlR2IDPConfig()
	return *idpCfg.GetSigner().Store.Value
}

func (c *VpWrapper) getCertificateForSinger() (cert *x509.Certificate, err error) {
	cfg := c.Provider.GetConfig()
	idpCfg, _ := cfg.ToSamlR2IDPConfig()

	signer := idpCfg.GetSigner()
	pass := signer.GetPassword()
	store := signer.GetStore()
	vl := store.GetValue()

	cert, _, err = DecodePkcs12(vl, pass)
	if err != nil {
		return nil, err
	}

	return cert, err
}

func (c *VpWrapper) KeystorePassword() string {
	cfg := c.Provider.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return err.Error()
	}

	singer := idpCfg.GetSigner()

	return singer.GetPassword()

}

func (c *VpWrapper) HasKeyPassword() bool {
	cfg := c.Provider.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return false
	}

	singer := idpCfg.GetSigner()

	return singer.GetPrivateKeyPassword() != ""
}

func (c *VpWrapper) KeyPassword() string {
	cfg := c.Provider.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return err.Error()
	}

	singer := idpCfg.GetSigner()

	return singer.GetPrivateKeyPassword()

}

func (c *VpWrapper) HasCertificateAlias() bool {
	cfg := c.Provider.GetConfig()
	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return false
	}

	singer := idpCfg.GetSigner()
	return singer.GetCertificateAlias() != ""

}

func (c *VpWrapper) CertificateAlias() string {
	cfg := c.Provider.GetConfig()
	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return err.Error()
	}

	singer := idpCfg.GetSigner()

	return singer.GetCertificateAlias()

}

func (c *VpWrapper) KeyAlias() string {
	cfg := c.Provider.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return err.Error()
	}

	encypter := idpCfg.GetEncrypter()
	aliaskey := encypter.GetPrivateKeyName()

	return aliaskey
}

func (c *VpWrapper) Certificate() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	certStr, err := util.CertificateToPEM(cert)
	return fmt.Sprint(certStr)
}

func (c *VpWrapper) Version() int {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return 0
	}

	return cert.Version
}

func (c *VpWrapper) SerialNumber() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	return cert.SerialNumber.String()
}

func (c *VpWrapper) Issuer() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	return cert.Issuer.String()
}

func (c *VpWrapper) Subjects() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	return cert.Subject.String()
}

func (c *VpWrapper) NotBefore() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}
	return cert.NotBefore.String()
}

func (c *VpWrapper) NotAfter() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	return cert.NotAfter.String()
}

func (c *VpWrapper) ElementId() string {
	return c.Provider.GetElementId()
}

func (c *VpWrapper) Type() string {
	return api.AsString(c.Provider.AdditionalProperties["@c"], "N/A")
}

func (c *VpWrapper) IdPs() []VPFcWrapper {

	var idps []VPFcWrapper

	for _, fc := range c.Provider.GetFederatedConnectionsB() {

		idpChannel, _ := fc.GetIDPChannel()
		idps = append(idps, VPFcWrapper{
			Preferred: idpChannel.GetPreferred(),
			IdP:       fc.GetName(),
			Fc:        &fc,
		})
	}

	return idps

}

// Federated Connection
func (c *VPFcWrapper) ChannelName() string {
	return c.Fc.ChannelB.GetName()
}

func (c *VPFcWrapper) AccountLinkage() string {
	idpChannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}
	return idpChannel.AccountLinkagePolicy.GetName()
}

func (c *VPFcWrapper) IdentityMapping() string {
	idpChannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}
	return idpChannel.IdentityMappingPolicy.GetName()
}

func (c *VPFcWrapper) OverrideProvider() bool {
	return c.Fc.ChannelB.GetOverrideProviderSetup()
}

func (c *VPFcWrapper) ConnectionName() string {
	return c.Fc.GetName()
}

func (c *VPFcWrapper) SignAuthenticationRequests() bool {
	idpChannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return false
	}
	return idpChannel.GetSignAuthenticationRequests()
}

func (c *VPFcWrapper) WantAssertionSigned() bool {
	idpChannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return false
	}
	return idpChannel.GetWantAssertionSigned()
}

func (c *VPFcWrapper) Bindings() string {
	// concatenate c.p.GetActiveBindings() as a single string
	return strings.Join(c.Fc.ChannelB.GetActiveBindings(), ", ")
}

func (c *VPFcWrapper) HttpPostBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_HTTP_POST")
}

func (c *VPFcWrapper) HttpRedirectBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_HTTP_REDIRECT")
}

func (c *VPFcWrapper) SoapBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_SOAP")
}

func (c *VPFcWrapper) ArtifactBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_ARTIFACT")
}

func (c *VPFcWrapper) LocalBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_LOCAL")
}

func (c *VPFcWrapper) HasBinding(b string) bool {
	for _, binding := range c.Fc.ChannelB.GetActiveBindings() {
		if binding == b {
			return true
		}
	}
	return false
}

func (c *VPFcWrapper) Location() string {
	l := c.Fc.ChannelB.GetLocation()
	return cli.LocationToStr(&l)
}

func (c *VPFcWrapper) Metadata() string {
	return c.Location() + "/SAML2/MD"
}

func (c *VPFcWrapper) IsPreferred() bool {
	return c.Preferred
}

func (c *VPFcWrapper) SignatureHash() string {

	idpchannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}

	return mapSaml2SignatureToTF(idpchannel.GetSignatureHash())
}

func (c *VPFcWrapper) MessageTTL() int32 {

	idpchannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return 0
	}

	return idpchannel.GetMessageTtl()
}

func (c *VPFcWrapper) MessageTTLTolerance() int32 {

	idpchannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return 0
	}

	return idpchannel.GetMessageTtlTolerance()
}

func (c *VPFcWrapper) EnableProxyExtension() bool {

	idpchannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return false
	}

	return idpchannel.GetEnableProxyExtension()
}
