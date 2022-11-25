package formatter

import (
	"crypto/x509"
	"encoding/base64"
	"strconv"

	api "github.com/atricore/josso-api-go"
	cli "github.com/atricore/josso-sdk-go"
)

type OidcRpWrapper struct {
	HeaderContext
	trunc bool
	p     *api.ExternalOpenIDConnectRelayingPartyDTO
}

const (
	OidcRpPrettyFormat = `
OIDC Relaying Party    

General 
	Name:                           {{.Name}}
	Id:                             {{.ID}}sa
	Description:                    {{.DisplayName}}
	Location:                       {{.Location}}
	Account Linkage:                {{.AccountLinkage}}
	Identity Mapping:				{{.IdentityMapping}}

	OIDC
		Client ID:                  {{.ClientId}}
		Secret:   					{{.Secret}}
		Public Key:				    {{.PublicKey}}
		Authentication:				{{.Authentication}}
		Redirect URIs:				{{.URIs}}
		Post logout redirectURIs:   {{.PostLogoutURIs}}
		Metadata:					{{.Metadata}}

		Protocol:
		Grants:					    {{.Grants}}
		Response Types:				{{.ResponseTypes}}
		Response Modes:				{{.ResponseModes}}
		Signature Algorithm:		{{.SignatureAlgorithm}}
		Encryption Algorithm:		{{.EncryptionAlgorithm}}
		Encryption Method:			{{.EncryptionMethod}}

		ID Token:
		Signature Algorithm:		{{.IDTokenSignatureAlgorithm}}
		Encryption Algorithm:		{{.IDTokenEncryptionAlgorithm}}
		Encryption Method:			{{.IDTokenEncryptionMethod}}

		Trusted IdPs:				{{.TrustedIdPs}}

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

func (c *OidcRpWrapper) Profiles() int {
	return len(c.p.GetActiveProfiles())
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
