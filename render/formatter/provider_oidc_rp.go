package formatter

import (
	"crypto/x509"
	"encoding/base64"
	"strconv"
	"strings"

	api "github.com/atricore/josso-api-go"
	cli "github.com/atricore/josso-sdk-go"
)

type OidcRpWrapper struct {
	HeaderContext
	trunc bool
	p     *api.ExternalOpenIDConnectRelayingPartyDTO
}

const (
	oidcRpTFFormat = `resource "iamtf_app_oidc" "{{.Name}}" {
		name = "{{.Name}}"
  }`
	OidcRpPrettyFormat = `
OIDC Relaying Party    

General 
	Name:                           {{.Name}}
	Id:                             {{.ID}}
	Description:                    {{.DisplayName}}
	Location:                       {{.Location}}
	Account Linkage:                {{.AccountLinkage}}
	Identity Mapping:               {{.IdentityMapping}}

    OIDC
        OP                          {{.Issuer}}
        OP Metadata:                {{.Metadata}}

        Client ID:                  {{.ClientId}}
        Public Key:                 {{.PublicKey}}
        Authentication:             {{.Authentication}}
        Redirect URIs:              {{.URIs}}
        Post logout redirectURIs:   {{.PostLogoutURIs}}
        
        Protocol                   
        Grants:                     {{.Grants}}
        Response Types:             {{.ResponseTypes}}
        Response Modes:             {{.ResponseModes}}
        Signature Algorithm:        {{.SignatureAlgorithm}}
        Encryption Algorithm:       {{.EncryptionAlgorithm}}
        Encryption Method:          {{.EncryptionMethod}}
        ID Token                   
        Signature Algorithm:        {{.IDTokenSignatureAlgorithm}}
        Encryption Algorithm:       {{.IDTokenEncryptionAlgorithm}}
        Encryption Method:          {{.IDTokenEncryptionMethod}}

    Trusted IdPs                    {{.TrustedIdPs}}

`
)

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewOidcRpFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultProviderTableFormat
		}
	case TFFormatKey:
		return oidcRpTFFormat
	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return OidcRpPrettyFormat
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

func OidcRpWrite(ctx ProviderContext, providers []api.ExternalOpenIDConnectRelayingPartyDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return OidcRpFormat(ctx, providers, format)
	}
	return ctx.Write(newOidcRpWrapper(), render)

}

func OidcRpFormat(ctx ProviderContext, providers []api.ExternalOpenIDConnectRelayingPartyDTO, format func(subContext SubContext) error) error {
	for _, provider := range providers {
		c := OidcRpWrapper{p: &provider}
		if err := format(&c); err != nil {
			return err
		}
	}
	return nil
}

func newOidcRpWrapper() *OidcRpWrapper {
	OidcRpWrapper := OidcRpWrapper{}
	OidcRpWrapper.Header = SubHeaderContext{
		"Name":     nameHeader,
		"Type":     typeHeader,
		"Location": locationHeader,
	}
	return &OidcRpWrapper
}

func (c *OidcRpWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

// General
func (c *OidcRpWrapper) Name() string {
	return c.p.GetName()
}

func (c *OidcRpWrapper) ID() string {

	id := strconv.FormatInt(c.p.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

func (c *OidcRpWrapper) DisplayName() string {
	return c.p.GetDisplayName()
}

func (c *OidcRpWrapper) Location() string {
	return cli.LocationToStr(c.p.Location)
}

func (c *OidcRpWrapper) Description() string {
	return c.p.GetDescription()
}

func (c *OidcRpWrapper) AccountLinkage() string {
	return c.p.AccountLinkagePolicy.GetName()
}

func (c *OidcRpWrapper) IdentityMapping() string {
	return c.p.IdentityMappingPolicy.GetName()
}

func (c *OidcRpWrapper) Profiles() int {
	return len(c.p.GetActiveProfiles())
}

func (c *OidcRpWrapper) ClientId() string {
	return c.p.GetClientId()
}

func (c *OidcRpWrapper) PublicKey() string {
	return c.p.GetClientCert()
}

func (c *OidcRpWrapper) Authentication() string {
	return c.p.GetClientAuthnMethod()
}

func (c *OidcRpWrapper) URIs() string {
	// join strings in a single value
	return strings.Join(c.p.GetAuthorizedURIs(), ", ")
}

func (c *OidcRpWrapper) PostLogoutURIs() string {
	// join strings in a single value
	return strings.Join(c.p.GetPostLogoutRedirectionURIs(), ", ")
}

func (c *OidcRpWrapper) Metadata() string {
	// http://localhost:8081/IDBUS/MYIAM-01/MY-APP-OP
	// http://localhost:8081/IDBUS/MYIAM-01/MY-APP
	return cli.LocationToStr(c.p.Location) + "-OP/OIDC/MD/.well-known/openid-configuration"
}

func (c *OidcRpWrapper) Issuer() string {
	// http://localhost:8081/IDBUS/MYIAM-01/MY-APP-OP
	// http://localhost:8081/IDBUS/MYIAM-01/MY-APP
	return cli.LocationToStr(c.p.Location) + "-OP/OIDC/MD"
}

// Print grants
func (c *OidcRpWrapper) Grants() string {
	return strings.Join(c.p.GetGrants(), ", ")
}

// Print response types
func (c *OidcRpWrapper) ResponseTypes() string {
	return strings.Join(c.p.GetResponseTypes(), ", ")
}

// Print response modes
func (c *OidcRpWrapper) ResponseModes() string {
	return "N/A"
}

// Print signature algorithm
func (c *OidcRpWrapper) SignatureAlgorithm() string {
	return c.p.GetSigningAlg()
}

// Print encryption algorithm
func (c *OidcRpWrapper) EncryptionAlgorithm() string {
	return c.p.GetEncryptionAlg()
}

// Print encryption method
func (c *OidcRpWrapper) EncryptionMethod() string {
	return c.p.GetEncryptionMethod()
}

// Print ID token signature algorithm
func (c *OidcRpWrapper) IDTokenSignatureAlgorithm() string {
	return c.p.GetIdTokenSigningAlg()
}

// Print ID token encryption algorithm
func (c *OidcRpWrapper) IDTokenEncryptionAlgorithm() string {
	return c.p.GetIdTokenEncryptionAlg()
}

// Print ID token encryption method
func (c *OidcRpWrapper) IDTokenEncryptionMethod() string {
	return c.p.GetIdTokenEncryptionMethod()
}

// Print trusted IdPs
func (c *OidcRpWrapper) TrustedIdPs() string {

	idps := ""
	for _, fc := range c.p.GetFederatedConnectionsB() {
		idps += fc.GetName() + ", "
	}
	return idps

}

func (c *OidcRpWrapper) FederatedConnections() []idpFcWrapper {
	var fcWrappers []idpFcWrapper
	for _, fc := range c.p.FederatedConnectionsA {
		fcWrappers = append(fcWrappers, idpFcWrapper{fc: &fc})
	}
	return fcWrappers
}

// keystore

func (c *OidcRpWrapper) getCertificateForSinger() (cert *x509.Certificate, err error) {
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
func (c *OidcRpWrapper) CertificateAlias() string {
	cfg := c.p.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return err.Error()
	}

	singer := idpCfg.GetSigner()

	return singer.GetCertificateAlias()

}

func (c *OidcRpWrapper) KeyAlias() string {
	cfg := c.p.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return err.Error()
	}

	encypter := idpCfg.GetEncrypter()

	aliaskey := encypter.GetPrivateKeyName()

	return aliaskey
}

func (c *OidcRpWrapper) Certificate() string {
	cert, err := c.getCertificateForSinger()
	if err != nil {
		return err.Error()
	}
	encodeCert := base64.StdEncoding.EncodeToString([]byte(cert.RawTBSCertificate))
	return encodeCert
}

func (c *OidcRpWrapper) ElementId() string {
	return c.p.GetElementId()
}
func (c *OidcRpWrapper) Type() string {
	return api.AsString(c.p.AdditionalProperties["@c"], "N/A")
}
