package formatter

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	api "github.com/atricore/josso-api-go"
	"github.com/atricore/josso-cli-go/saml"
	cli "github.com/atricore/josso-sdk-go"
)

type ExtSaml2SpWrapper struct {
	HeaderContext
	trunc     bool
	IdaName   string
	Provider  *api.ExternalSaml2ServiceProviderDTO
	Container *api.ProviderContainerDTO
}

const (
	extSaml2SpTFFormat = `resource "iamtf_app_saml2" "{{.AppName}}" {
	ida         = "{{.ApplianceName}}"
	name        = "{{.AppName}}"
	description = "{{.DisplayName}}"

	{{ range $idp := .IdPs }}
	idp {
		name         = "{{ $idp.IdP }}"
		is_preferred = {{ $idp.Preferred }}
	}
	{{- end}}

	metadata	= "{{.ExtMetadataB64}}"

}`
	ExtSaml2SpPrettyFormat = `
SAML Service Provider (external)    

General 
    Name:                               {{.Name}}
    Description :                       {{.DisplayName}}
	Identity Providers:
	{{ range $idp := .IdPs }}           
	                                    {{ $idp.IdP }}, preferred: {{ $idp.Preferred }}
	{{- end}}
    SAML2    
        Entity ID:                      {{.EntityID}}

        Endpoints:
                                        {{ range $e := .Endpoints }}
            Type:                       {{$e.Type}}
            Binding:                    {{$e.Binding}}
            URL:                        {{$e.URL}}
            Response:                   {{$e.ResponseURL}}
                                        {{ end }} 
            Certificates:               {{- if $.HasSignCert }}
                Signing:                {{.SignCertificate}}
                    Issuer:             {{.SignIssuer}}
                    Not Before:         {{.SignNotBefore}}
                    Not After:          {{.SignNotAfter}}
				{{- end}}               {{- if $.HasEncryptCert }}
                Encryption:             {{.EncryptCertificate}}
                    Issuer:             {{.EncryptIssuer}}
                    Not Before:         {{.EncryptNotBefore}}
                    Not After:          {{.EncryptNotAfter}}
			{{- end}}
`
)

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewExtSaml2SpFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultProviderTableFormat
		}
	case TFFormatKey:
		return extSaml2SpTFFormat
	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return ExtSaml2SpPrettyFormat
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

func ExtSaml2SpWrite(ctx ProviderContext, providers []ExtSaml2SpWrapper) error {
	render := func(format func(subContext SubContext) error) error {
		return extSaml2SpFormat(ctx, providers, format)
	}
	return ctx.Write(newExtSaml2SpWrapper(), render)

}

func extSaml2SpFormat(ctx ProviderContext, providers []ExtSaml2SpWrapper, format func(subContext SubContext) error) error {
	for _, provider := range providers {
		if err := format(&provider); err != nil {
			return err
		}
	}
	return nil
}

func newExtSaml2SpWrapper() *ExtSaml2SpWrapper {
	ExtSaml2SpWrapper := ExtSaml2SpWrapper{}
	ExtSaml2SpWrapper.Header = SubHeaderContext{
		"Name":     nameHeader,
		"Type":     typeHeader,
		"Location": locationHeader,
	}
	return &ExtSaml2SpWrapper
}

func (c *ExtSaml2SpWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

// General
func (c *ExtSaml2SpWrapper) ApplianceName() string {
	return c.IdaName
}

func (c *ExtSaml2SpWrapper) Name() string {
	return c.Provider.GetName()
}

func (c *ExtSaml2SpWrapper) AppName() string {
	return *c.Container.Name
}

func (c *ExtSaml2SpWrapper) ID() string {

	id := strconv.FormatInt(c.Provider.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

func (c *ExtSaml2SpWrapper) DisplayName() string {
	return c.Provider.GetDisplayName()
}

func (c *ExtSaml2SpWrapper) Location() string {
	return cli.LocationToStr(c.Provider.Location)
}

func (c *ExtSaml2SpWrapper) Description() string {
	return c.Provider.GetDescription()
}

// SAML2
func (c *ExtSaml2SpWrapper) Metadata() string {
	return fmt.Sprintf("%s/SAML2/MD", c.Location())
}

func (c *ExtSaml2SpWrapper) EntityID() string {
	m := c.ExtMetadataB64()
	id, err := saml.GetEntityIDFromStr(m)
	if err != nil {
		return err.Error()
	}

	return id

}

func (c *ExtSaml2SpWrapper) Bindings() string {
	// concatenate c.p.GetActiveBindings() as a single string
	return strings.Join(c.Provider.GetActiveBindings(), ", ")
}

func (c *ExtSaml2SpWrapper) FederatedConnections() []SPFcWrapper {
	var fcWrappers []SPFcWrapper
	for i := range c.Provider.FederatedConnectionsB {
		fcWrappers = append(fcWrappers, SPFcWrapper{Fc: &c.Provider.FederatedConnectionsB[i]})
	}
	return fcWrappers
}

// keystore

func (c *ExtSaml2SpWrapper) getCertificateForSinger() (cert *x509.Certificate, err error) {
	cfg := c.Provider.GetConfig()

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

func (c *ExtSaml2SpWrapper) HasSignCert() bool {
	r, _, err := saml.GetProviderCertificatesFromStr(c.ExtMetadataB64())
	if err != nil {
		return false
	}

	if r == nil {
		return true
	}

	return true
}

func (c *ExtSaml2SpWrapper) HasEncryptCert() bool {
	_, r, err := saml.GetProviderCertificatesFromStr(c.ExtMetadataB64())
	if err != nil {
		return false
	}

	if r == nil {
		return true
	}

	return true
}

func (c *ExtSaml2SpWrapper) SignCertificate() string {
	s, _, err := saml.GetProviderCertificatesFromStr(c.ExtMetadataB64())
	if err != nil {
		return err.Error()
	}

	if s == nil {
		return "No signing certificate found"
	}

	return s.SerialNumber.String()
}

func (c *ExtSaml2SpWrapper) SignIssuer() string {
	s, _, err := saml.GetProviderCertificatesFromStr(c.ExtMetadataB64())
	if err != nil {
		return err.Error()
	}

	if s == nil {
		return "No signing certificate found"
	}

	return s.Issuer.CommonName
}

func (c *ExtSaml2SpWrapper) SignNotBefore() string {
	s, _, err := saml.GetProviderCertificatesFromStr(c.ExtMetadataB64())
	if err != nil {
		return err.Error()
	}

	if s == nil {
		return "No signing certificate found"
	}

	return s.NotBefore.String()
}

func (c *ExtSaml2SpWrapper) SignNotAfter() string {
	s, _, err := saml.GetProviderCertificatesFromStr(c.ExtMetadataB64())
	if err != nil {
		return err.Error()
	}

	if s == nil {
		return "No signing certificate found"
	}

	return s.NotAfter.String()
}

func (c *ExtSaml2SpWrapper) EncryptCertificate() string {
	_, s, err := saml.GetProviderCertificatesFromStr(c.ExtMetadataB64())
	if err != nil {
		return err.Error()
	}

	if s == nil {
		return "No encryption certificate found"
	}

	return s.SerialNumber.String()
}

func (c *ExtSaml2SpWrapper) EncryptIssuer() string {
	_, s, err := saml.GetProviderCertificatesFromStr(c.ExtMetadataB64())
	if err != nil {
		return err.Error()
	}

	if s == nil {
		return "No signing certificate found"
	}

	return s.Issuer.CommonName
}

func (c *ExtSaml2SpWrapper) EncryptNotBefore() string {
	_, s, err := saml.GetProviderCertificatesFromStr(c.ExtMetadataB64())
	if err != nil {
		return err.Error()
	}

	if s == nil {
		return "No signing certificate found"
	}

	return s.NotBefore.String()
}

func (c *ExtSaml2SpWrapper) EncryptNotAfter() string {
	_, s, err := saml.GetProviderCertificatesFromStr(c.ExtMetadataB64())
	if err != nil {
		return err.Error()
	}

	if s == nil {
		return "No signing certificate found"
	}

	return s.NotAfter.String()
}

func (c *ExtSaml2SpWrapper) ElementId() string {
	return c.Provider.GetElementId()
}
func (c *ExtSaml2SpWrapper) Type() string {
	return api.AsString(c.Provider.AdditionalProperties["@c"], "N/A")
}

func (c *ExtSaml2SpWrapper) Endpoints() []saml.SAMLEndpoint {

	var endpoints []saml.SAMLEndpoint

	endpoints, err := saml.GetSPEndpointsFromStr(c.ExtMetadataB64())
	if err != nil {
		// TODO : Handle error
		fmt.Println("Error:", err)
	}
	return endpoints
}

func (c *ExtSaml2SpWrapper) ExtMetadata() string {
	if m, ok := c.Provider.GetMetadataOk(); ok {
		if v, ok := m.GetValueOk(); ok {
			decoded, err := base64.StdEncoding.DecodeString(*v)
			if err != nil {
				//fmt.Println("decode error:", err)
				return "Error decoding metadata" + err.Error()
			}
			return string(decoded)
		}
	}
	return "N/A"
}

func (c *ExtSaml2SpWrapper) ExtMetadataB64() string {
	if m, ok := c.Provider.GetMetadataOk(); ok {
		if v, ok := m.GetValueOk(); ok {
			return *v
		}
	}
	return "N/A"
}

func (c *ExtSaml2SpWrapper) IdPs() []SPFcWrapper {

	var idps []SPFcWrapper

	for _, fc := range c.Provider.GetFederatedConnectionsB() {
		idps = append(idps, SPFcWrapper{
			Preferred: false,
			IdP:       fc.GetName(),
			Fc:        &fc,
		})
	}

	return idps

}
