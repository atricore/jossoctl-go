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
	trunc bool
	p     *api.InternalSaml2ServiceProviderDTO
}

type spFcWrapper struct {
	fc *api.FederatedConnectionDTO
}

const (
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

func IntSaml2SpWrite(ctx ProviderContext, providers []api.InternalSaml2ServiceProviderDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return intSaml2SpFormat(ctx, providers, format)
	}
	return ctx.Write(newIntSaml2SpWrapper(), render)

}

func intSaml2SpFormat(ctx ProviderContext, providers []api.InternalSaml2ServiceProviderDTO, format func(subContext SubContext) error) error {
	for _, provider := range providers {
		c := IntSaml2SpWrapper{p: &provider}
		if err := format(&c); err != nil {
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
	return c.p.GetName()
}

func (c *IntSaml2SpWrapper) ID() string {

	id := strconv.FormatInt(c.p.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

func (c *IntSaml2SpWrapper) DisplayName() string {
	return c.p.GetDisplayName()
}

func (c *IntSaml2SpWrapper) Location() string {
	return cli.LocationToStr(c.p.Location)
}

func (c *IntSaml2SpWrapper) Description() string {
	return c.p.GetDescription()
}

func (c *IntSaml2SpWrapper) AccountLinkage() string {
	return c.p.AccountLinkagePolicy.GetName()
}

func (c *IntSaml2SpWrapper) IdentityMapping() string {
	return c.p.IdentityMappingPolicy.GetName()
}

func (c *IntSaml2SpWrapper) DashboardURL() string {
	return c.p.GetDashboardUrl()
}
func (c *IntSaml2SpWrapper) ErrorBinding() string {
	return c.p.GetErrorBinding()
}

// SAML2
func (c *IntSaml2SpWrapper) Metadata() string {
	return fmt.Sprintf("%s/SAML2/MD", c.Location())
}

func (c *IntSaml2SpWrapper) Bindings() string {
	// concatenate c.p.GetActiveBindings() as a single string
	return strings.Join(c.p.GetActiveBindings(), ", ")
}

func (c *IntSaml2SpWrapper) SingAuthnReq() bool {
	return c.p.GetSignAuthenticationRequests()
}

func (c *IntSaml2SpWrapper) WantAssertionSigned() bool {
	return c.p.GetWantAssertionSigned()
}

func (c *IntSaml2SpWrapper) WantRequestSigned() bool {
	return c.p.GetWantSignedRequests()
}

func (c *IntSaml2SpWrapper) SignRequests() bool {
	return c.p.GetSignRequests()
}

func (c *IntSaml2SpWrapper) MessageTTL() int32 {
	return c.p.GetMessageTtl()
}

func (c *IntSaml2SpWrapper) MessageTTLTolerance() int32 {
	return c.p.GetMessageTtlTolerance()
}

func (c *IntSaml2SpWrapper) Profiles() int {
	return len(c.p.GetActiveProfiles())
}

func (c *IntSaml2SpWrapper) SignatureHash() string {
	return c.p.GetSignatureHash()
}

func (c *IntSaml2SpWrapper) FederatedConnections() []spFcWrapper {
	var fcWrappers []spFcWrapper
	for i := range c.p.FederatedConnectionsB {
		fcWrappers = append(fcWrappers, spFcWrapper{fc: &c.p.FederatedConnectionsB[i]})
	}
	return fcWrappers
}

// keystore

func (c *IntSaml2SpWrapper) getCertificateForSinger() (cert *x509.Certificate, err error) {
	cfg := c.p.GetConfig()

	idpCfg, _ := cfg.ToSamlR2SPConfig()

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
func (c *IntSaml2SpWrapper) CertificateAlias() string {
	cfg := c.p.GetConfig()

	idpCfg, err := cfg.ToSamlR2SPConfig()
	if err != nil {
		return err.Error()
	}

	singer := idpCfg.GetSigner()

	return singer.GetCertificateAlias()

}

func (c *IntSaml2SpWrapper) KeyAlias() string {
	cfg := c.p.GetConfig()

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
	return c.p.GetElementId()
}
func (c *IntSaml2SpWrapper) Type() string {
	return api.AsString(c.p.AdditionalProperties["@c"], "N/A")
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
