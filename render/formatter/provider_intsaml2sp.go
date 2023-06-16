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

type IntSaml2SpWrapper struct {
	HeaderContext
	trunc     bool
	IdaName   string
	Provider  *api.InternalSaml2ServiceProviderDTO
	Resource  *api.JOSSO1ResourceDTO
	Container *api.ProviderContainerDTO
}

type spFcWrapper struct {
	fc *api.FederatedConnectionDTO
}

const (
	intSaml2SpTFFormat = `resource "iamtf_app_agent" "{{.AppName}}" {
	ida                   = "{{.ApplianceName}}"
	name                  = "{{.AppName}}"
	sp_id                 = "{{.SpId}}"
	description           = "{{.DisplayName}}"

	app_location          = "{{.AppLocation}}"
	{{- if .HasSloLocation}}
	app_slo_location      = "{{.SloLocation}}"
	{{- end}}
	{{- if .HasDefaultResource}}
	default_resource      = "{{.DefaultResource}}"
	{{- end}}
	{{- if .HasIgnoredWebResources}}
	ignored_web_resources = [{{.IgnoredWebResources}}]
	{{- end}}
	exec_env              = "{{.ExecEnv}}"
	error_binding         = "{{.ErrorBinding}}"
	{{- if .HasDashboardURL}}
	dashboard_url         = "{{.DashboardURL}}" 
	{{- end}}

	` + spSaml2TFFormat + `

	{{ range $idp := .IdPs }}
	idp {
		name         = "{{ $idp.IdP }}"
		is_preferred = {{ $idp.Preferred }}
		{{- if $idp.SpFc.OverrideProvider}}
		` + spSaml2TFFormat + `
		{{- end}}				
	}
	{{- end}}

	
	
	` + keystoreTFFormat + `
}`

	spSaml2TFFormat = `	saml2 {
		account_linkage              = "{{.Saml2AccountLinkage}}"
		identity_mapping             = "{{.Saml2IdentityMapping}}"

		sign_requests                = {{.SignRequests}}
		sign_authentication_requests = {{.SingAuthnReq}}
		want_assertion_signed        = {{.WantAssertionSigned}}
		signature_hash               = "{{.SignatureHash}}"

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

	IntSaml2SpPrettyFormat = `
SAML Service Provider (built-in)    

General 
    Name:                               {{.Name}}
    Description :                       {{.DisplayName}}
    Location:                           {{.Location}}
    Account linkage:                    {{.AccountLinkage}}	
    Identity mapping:                   {{.IdentityMapping}}
    Dashboard URL:                      {{.DashboardURL}}
    Error Binding:                      {{.ErrorBinding}}    

    SAML2    
        Metadata:                       {{.Metadata}}        
        Bindings:                       {{.Bindings}}
        Sing auth request:              {{.SingAuthnReq}}
        Want assertion signed:          {{.WantAssertionSigned}}
        Want request signed:            {{.WantRequestSigned}}
        Sign requests:                  {{.SignRequests}}
        Signature hash:                 {{.SignatureHash}}
        Message TTL:                    {{.MessageTTL}}
        External Msg TTL Tolerance:     {{.MessageTTLTolerance}}        
        
    Federated connections {{ range $fc := .FederatedConnections}}
    	IDP Channel:                    {{$fc.ChannelName}}
    	Target Provider:                {{$fc.ConnectionName}}		
    	Preferred:                      {{$fc.Preferred}}
    	Override provider setup:        {{$fc.OverrideProvider}}
    	{{- if $fc.OverrideProvider }}
    	Account linkage:                {{$fc.AccountLinkage}}
    	Identity mapping:               {{$fc.IdentityMapping}}

        SAML 2
            Metadata:                   {{$fc.Metadata}}        
            Bindings:                   {{$fc.Bindings}}
    	    Sing authn request:         {{$fc.SignAuthenticationRequests}}
    	    Want assertion Signed:      {{$fc.WantAssertionSigned}}
    	    Signature hash:             {{$fc.SignatureHash}}
    	    Message TTL:                {{$fc.MessageTTL}}
    	    External msg TTL tolerance: {{$fc.MessageTTLTolerance}}
    	    Enable proxy Extension:     {{$fc.EnableProxyExtension}}
    	{{ end }}{{ end }}

` + keystoreFormat
)

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewIntSaml2SpFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultProviderTableFormat
		}
	case TFFormatKey:
		return intSaml2SpTFFormat
	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return IntSaml2SpPrettyFormat
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

func IntSaml2SpWrite(ctx ProviderContext, providers []IntSaml2SpWrapper) error {
	render := func(format func(subContext SubContext) error) error {
		return intSaml2SpFormat(ctx, providers, format)
	}
	return ctx.Write(newIntSaml2SpWrapper(), render)

}

func intSaml2SpFormat(ctx ProviderContext, providers []IntSaml2SpWrapper, format func(subContext SubContext) error) error {
	for _, provider := range providers {
		if err := format(&provider); err != nil {
			return err
		}
	}
	return nil
}

func newIntSaml2SpWrapper() *IntSaml2SpWrapper {
	IntSaml2SpWrapper := IntSaml2SpWrapper{}
	IntSaml2SpWrapper.Header = SubHeaderContext{
		"Name":     nameHeader,
		"Type":     typeHeader,
		"Location": locationHeader,
	}
	return &IntSaml2SpWrapper
}

func (c *IntSaml2SpWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

// General
func (c *IntSaml2SpWrapper) Name() string {
	return c.Provider.GetName()
}

func (c *IntSaml2SpWrapper) SpId() string {

	return *c.Provider.Name
}

func (c *IntSaml2SpWrapper) ApplianceName() string {
	return c.IdaName
}

func (c *IntSaml2SpWrapper) AppName() string {

	// This is a LONG path to get the name of the resource
	//fmt.Printf("sp properties : %+v\n", c.Container.FederatedProvider.AdditionalProperties)
	//fmt.Printf("sc properties : %+v\n", c.Container.FederatedProvider.AdditionalProperties["serviceConnection"])

	scMap, ok := c.Container.FederatedProvider.AdditionalProperties["serviceConnection"].(map[string]interface{})
	if !ok {
		return "ERROR (service connection not found)"
	}
	return scMap["name"].(string)
	/*
		//fmt.Printf("rs properties: %+v\n", scMap["resource"])

		rMap, ok := scMap["resource"].(map[string]interface{})
		//fmt.Printf("rs name: %s\n", rMap["name"])
		if !ok {
			return "ERROR (resource not found)"
		}

		return rMap["name"].(string)
	*/
}

func (c *IntSaml2SpWrapper) ID() string {

	id := strconv.FormatInt(c.Provider.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

func (c *IntSaml2SpWrapper) DisplayName() string {
	return c.Provider.GetDisplayName()
}

func (c *IntSaml2SpWrapper) Location() string {
	return cli.LocationToStr(c.Provider.Location)
}

func (c *IntSaml2SpWrapper) AppLocation() string {
	return cli.LocationToStr(c.Resource.PartnerAppLocation)
}

func (c *IntSaml2SpWrapper) HasSloLocation() bool {
	return c.Resource.GetSloLocationEnabled()
}

func (c *IntSaml2SpWrapper) SloLocation() string {
	return cli.LocationToStr(c.Resource.SloLocation)
}

func (c *IntSaml2SpWrapper) HasDefaultResource() bool {
	return c.Resource.DefaultResource != nil
}

func (c *IntSaml2SpWrapper) DefaultResource() string {
	return c.Resource.GetDefaultResource()
}

func (c *IntSaml2SpWrapper) ExecEnv() string {
	return *c.Resource.Activation.Name
}

func (c *IntSaml2SpWrapper) Description() string {
	return c.Provider.GetDescription()
}

func (c *IntSaml2SpWrapper) HasIgnoredWebResources() bool {
	return len(c.Resource.IgnoredWebResources) > 0
}

func (c *IntSaml2SpWrapper) IgnoredWebResources() string {
	return strings.Join(c.Resource.GetIgnoredWebResources(), ", ")
}

func (c *IntSaml2SpWrapper) AccountLinkage() string {
	return c.Provider.AccountLinkagePolicy.GetName()
}

func (c *IntSaml2SpWrapper) Saml2AccountLinkage() string {
	return c.Provider.AccountLinkagePolicy.GetLinkEmitterType()
}

func (c *IntSaml2SpWrapper) IdentityMapping() string {
	return c.Provider.IdentityMappingPolicy.GetName()
}

func (c *IntSaml2SpWrapper) Saml2IdentityMapping() string {
	return c.Provider.IdentityMappingPolicy.GetMappingType()
}

func (c *IntSaml2SpWrapper) DashboardURL() string {
	return c.Provider.GetDashboardUrl()
}

func (c *IntSaml2SpWrapper) HasDashboardURL() bool {
	return c.Provider.GetDashboardUrl() != ""
}

func (c *IntSaml2SpWrapper) ErrorBinding() string {
	return c.Provider.GetErrorBinding()
}

// SAML2
func (c *IntSaml2SpWrapper) Metadata() string {
	return fmt.Sprintf("%s/SAML2/MD", c.Location())
}

func (c *IntSaml2SpWrapper) Bindings() string {
	// concatenate c.p.GetActiveBindings() as a single string
	return strings.Join(c.Provider.GetActiveBindings(), ", ")
}

func (c *IntSaml2SpWrapper) HttpPostBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_HTTP_POST")
}

func (c *IntSaml2SpWrapper) HttpRedirectBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_HTTP_REDIRECT")
}

func (c *IntSaml2SpWrapper) SoapBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_SOAP")
}

func (c *IntSaml2SpWrapper) ArtifactBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_ARTIFACT")
}

func (c *IntSaml2SpWrapper) LocalBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_LOCAL")
}

func (c *IntSaml2SpWrapper) HasBinding(b string) bool {
	for _, binding := range c.Provider.GetActiveBindings() {
		if binding == b {
			return true
		}
	}
	return false
}

func (c *IntSaml2SpWrapper) SingAuthnReq() bool {
	return c.Provider.GetSignAuthenticationRequests()
}

func (c *IntSaml2SpWrapper) WantAssertionSigned() bool {
	return c.Provider.GetWantAssertionSigned()
}

func (c *IntSaml2SpWrapper) WantRequestSigned() bool {
	return c.Provider.GetWantSignedRequests()
}

func (c *IntSaml2SpWrapper) SignRequests() bool {
	return c.Provider.GetSignRequests()
}

func (c *IntSaml2SpWrapper) MessageTTL() int32 {
	return c.Provider.GetMessageTtl()
}

func (c *IntSaml2SpWrapper) MessageTTLTolerance() int32 {
	return c.Provider.GetMessageTtlTolerance()
}

func (c *IntSaml2SpWrapper) Profiles() int {
	return len(c.Provider.GetActiveProfiles())
}

func (c *IntSaml2SpWrapper) SignatureHash() string {
	return c.Provider.GetSignatureHash()
}

func (c *IntSaml2SpWrapper) FederatedConnections() []spFcWrapper {
	var fcWrappers []spFcWrapper
	for i := range c.Provider.FederatedConnectionsB {
		fcWrappers = append(fcWrappers, spFcWrapper{fc: &c.Provider.FederatedConnectionsB[i]})
	}
	return fcWrappers
}

func (c *IntSaml2SpWrapper) HasKeystore() bool {
	cfg := c.Provider.GetConfig()
	spCfg, _ := cfg.ToSamlR2SPConfig()
	return !spCfg.GetUseSampleStore() && !spCfg.GetUseSystemStore()
}

func (c *IntSaml2SpWrapper) KeystoreResource() string {
	cfg := c.Provider.GetConfig()
	spCfg, _ := cfg.ToSamlR2SPConfig()
	return *spCfg.GetSigner().Store.Value
}

func (c *IntSaml2SpWrapper) getCertificateForSinger() (cert *x509.Certificate, err error) {
	cfg := c.Provider.GetConfig()
	spCfg, _ := cfg.ToSamlR2SPConfig()

	signer := spCfg.GetSigner()
	pass := signer.GetPassword()
	store := signer.GetStore()
	vl := store.GetValue()

	cert, _, err = DecodePkcs12(vl, pass)
	if err != nil {
		return nil, err
	}

	return cert, err
}

func (c *IntSaml2SpWrapper) KeystorePassword() string {
	cfg := c.Provider.GetConfig()

	idpCfg, err := cfg.ToSamlR2SPConfig()
	if err != nil {
		return err.Error()
	}

	singer := idpCfg.GetSigner()

	return singer.GetPassword()

}

func (c *IntSaml2SpWrapper) HasKeyPassword() bool {
	cfg := c.Provider.GetConfig()

	idpCfg, err := cfg.ToSamlR2SPConfig()
	if err != nil {
		return false
	}

	singer := idpCfg.GetSigner()

	return singer.GetPrivateKeyPassword() != ""
}

func (c *IntSaml2SpWrapper) KeyPassword() string {
	cfg := c.Provider.GetConfig()

	idpCfg, err := cfg.ToSamlR2SPConfig()
	if err != nil {
		return err.Error()
	}

	singer := idpCfg.GetSigner()

	return singer.GetPrivateKeyPassword()

}

func (c *IntSaml2SpWrapper) HasCertificateAlias() bool {
	cfg := c.Provider.GetConfig()
	idpCfg, err := cfg.ToSamlR2SPConfig()
	if err != nil {
		return false
	}

	singer := idpCfg.GetSigner()
	return singer.GetCertificateAlias() != ""

}

func (c *IntSaml2SpWrapper) CertificateAlias() string {
	cfg := c.Provider.GetConfig()
	idpCfg, err := cfg.ToSamlR2SPConfig()
	if err != nil {
		return err.Error()
	}

	singer := idpCfg.GetSigner()

	return singer.GetCertificateAlias()

}

func (c *IntSaml2SpWrapper) KeyAlias() string {
	cfg := c.Provider.GetConfig()

	idpCfg, err := cfg.ToSamlR2SPConfig()
	if err != nil {
		return err.Error()
	}

	encypter := idpCfg.GetEncrypter()
	aliaskey := encypter.GetPrivateKeyName()

	return aliaskey
}

func (c *IntSaml2SpWrapper) Certificate() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	certStr, err := util.CertificateToPEM(cert)
	return fmt.Sprint(certStr)
}

func (c *IntSaml2SpWrapper) Version() int {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return 0
	}

	return cert.Version
}

func (c *IntSaml2SpWrapper) SerialNumber() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	return cert.SerialNumber.String()
}

func (c *IntSaml2SpWrapper) Issuer() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	return cert.Issuer.String()
}

func (c *IntSaml2SpWrapper) Subjects() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	return cert.Subject.String()
}

func (c *IntSaml2SpWrapper) NotBefore() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}
	return cert.NotBefore.String()
}

func (c *IntSaml2SpWrapper) NotAfter() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}

	return cert.NotAfter.String()
}

func (c *IntSaml2SpWrapper) ElementId() string {
	return c.Provider.GetElementId()
}

func (c *IntSaml2SpWrapper) Type() string {
	return api.AsString(c.Provider.AdditionalProperties["@c"], "N/A")
}

func (c *IntSaml2SpWrapper) IdPs() []FederatedConnectionToIdP {

	var idps []FederatedConnectionToIdP

	for _, fc := range c.Provider.GetFederatedConnectionsB() {
		idps = append(idps, FederatedConnectionToIdP{
			Preferred: false,
			IdP:       fc.GetName(),
			SpFc: spFcWrapper{
				&fc,
			},
		})
	}

	return idps

}

// Federated Connection
func (c *spFcWrapper) ChannelName() string {
	return c.fc.ChannelB.GetName()
}

func (c *spFcWrapper) AccountLinkage() string {
	idpChannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}
	return idpChannel.AccountLinkagePolicy.GetName()
}

func (c *spFcWrapper) IdentityMapping() string {
	idpChannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}
	return idpChannel.IdentityMappingPolicy.GetName()
}

func (c *spFcWrapper) OverrideProvider() bool {
	return c.fc.ChannelB.GetOverrideProviderSetup()
}

func (c *spFcWrapper) ConnectionName() string {
	return c.fc.GetName()
}

func (c *spFcWrapper) SignAuthenticationRequests() bool {
	idpChannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return false
	}
	return idpChannel.GetSignAuthenticationRequests()
}

func (c *spFcWrapper) WantAssertionSigned() bool {
	idpChannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return false
	}
	return idpChannel.GetWantAssertionSigned()
}

func (c *spFcWrapper) Bindings() string {
	// concatenate c.p.GetActiveBindings() as a single string
	return strings.Join(c.fc.ChannelB.GetActiveBindings(), ", ")
}

func (c *spFcWrapper) Location() string {
	l := c.fc.ChannelB.GetLocation()
	return cli.LocationToStr(&l)
}

func (c *spFcWrapper) Metadata() string {
	return c.Location() + "/SAML2/MD"
}

func (c *spFcWrapper) Preferred() bool {
	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return false
	}
	return idpchannel.GetPreferred()
}

func (c *spFcWrapper) SignatureHash() string {

	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}

	return idpchannel.GetSignatureHash()
}

func (c *spFcWrapper) MessageTTL() int32 {

	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return 0
	}

	return idpchannel.GetMessageTtl()
}

func (c *spFcWrapper) MessageTTLTolerance() int32 {

	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return 0
	}

	return idpchannel.GetMessageTtlTolerance()
}

func (c *spFcWrapper) EnableProxyExtension() bool {

	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return false
	}

	return idpchannel.GetEnableProxyExtension()
}
