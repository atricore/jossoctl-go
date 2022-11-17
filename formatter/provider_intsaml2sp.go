package formatter

import (
	"crypto/x509"
	"encoding/base64"
	"strconv"

	api "github.com/atricore/josso-api-go"
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
	Name:                           {{.Name}}
	Id:                             {{.ID}}sa
	Display Name:                   {{.DisplayName}}
	Location:                       {{.Location}}
	Account Linkage:                {{.AccountLinkage}}
	Groups as multi-valued:
	Properties as multi-valued:
	Internal Attrs as multi-valued:
	Dashboard URL:                  {{.DashboardURL}}
	Error Binding:                  {{.ErrorBinding}}

	SAML2

		Metadata Svc:               {{.MetadataSVC}}
		Profiles:					{{.Profiles}}
		Binding:                    {{.Binding}}
		{{ range $fc := .FederatedConnections}}
		Sing AuthnReq:              {{$fc.SingAuthnReq}}
		Signature Hash:             {{$fc.SignatureHash}}
		Message TTL:                {{$fc.MessageTTL}}
		External Msg TTL Tolerance: {{$fc.MessageTTLTolerance}}
		{{ end }}

		Keystore
		Certificate Alias:	{{.CertificateAlias}}
		Key alias:			{{.KeyAlias}}
		Certificate:		{{.Certificate}}

	Federated connections
	-----------
		IDP Channel
			{{ range $fc := .FederatedConnections}}
			Connection Name:	{{$fc.ConnectionName}}
			Channel Name:		{{$fc.ChannelName}}
			Preferred::			{{$fc.Prefered}}
			{{ end }}

		EXTRAS:
		Type:       {{.Type}}
		Description {{.Description}}
		ElementId   {{.ElementId}}
`
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
		var formatted []SubContext
		formatted = []SubContext{}
		c := IntSaml2SpWrapper{
			p: &provider,
		}
		formatted = append(formatted, &c)

		for _, providerCtx := range formatted {
			if err := format(providerCtx); err != nil {
				return err
			}
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

func (c *IntSaml2SpWrapper) DashboardURL() string {
	return c.p.GetDashboardUrl()
}
func (c *IntSaml2SpWrapper) ErrorBinding() string {
	return c.p.GetErrorBinding()
}

// SAML2
func (c *IntSaml2SpWrapper) MetadataSVC() bool {
	return c.p.GetEnableMetadataEndpoint()
}

func (c *IntSaml2SpWrapper) Profiles() int {
	return len(c.p.GetActiveProfiles())
}

func (c *IntSaml2SpWrapper) FederatedConnections() []idpFcWrapper {
	var fcWrappers []idpFcWrapper
	for _, fc := range c.p.FederatedConnectionsA {
		fcWrappers = append(fcWrappers, idpFcWrapper{fc: &fc})
	}
	return fcWrappers
}

func (c *spFcWrapper) SingAuthnReq() bool {

	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return false
	}

	return idpchannel.GetSignAuthenticationRequests()
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

func (c *spFcWrapper) MessageTTLToleranceL() int32 {

	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return 0
	}

	return idpchannel.GetMessageTtlTolerance()
}

// keystore

func (c *IntSaml2SpWrapper) getCertificateForSinger() (cert *x509.Certificate, err error) {
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
func (c *IntSaml2SpWrapper) CertificateAlias() string {
	cfg := c.p.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
	if err != nil {
		return err.Error()
	}

	singer := idpCfg.GetSigner()

	return singer.GetCertificateAlias()

}

func (c *IntSaml2SpWrapper) KeyAlias() string {
	cfg := c.p.GetConfig()

	idpCfg, err := cfg.ToSamlR2IDPConfig()
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
	encodeCert := base64.StdEncoding.EncodeToString([]byte(cert.RawTBSCertificate))
	return encodeCert
}

func (c *IntSaml2SpWrapper) ElementId() string {
	return c.p.GetElementId()
}
func (c *IntSaml2SpWrapper) Type() string {
	return api.AsString(c.p.AdditionalProperties["@c"], "N/A")
}

// Federated Connection
func (c *spFcWrapper) ChannelName() string {

	return c.fc.ChannelA.GetName()
}

func (c *spFcWrapper) ConnectionName() string {
	return c.fc.GetName()
}

func (c *spFcWrapper) Prefered() bool {
	idpchannel, err := c.fc.GetIDPChannel()
	if err != nil {
		return false
	}
	return idpchannel.GetPreferred()
}
