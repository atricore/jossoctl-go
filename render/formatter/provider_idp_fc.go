package formatter

import (
	"strings"

	api "github.com/atricore/josso-api-go"
	cli "github.com/atricore/josso-sdk-go"
)

/**
 * Wrap a connection to a service provider (FC -> channelA as SPChannel)
 */
type IdPFcWrapper struct {
	idx       int
	Override  bool
	Preferred bool
	/* target service provider */
	SP string
	Fc *api.FederatedConnectionDTO
}

// SPs
func (c *idPWrapper) SPs() []IdPFcWrapper {

	var sps []IdPFcWrapper

	for _, fc := range c.Provider.GetFederatedConnectionsA() {

		if fc.ChannelA.GetOverrideProviderSetup() {
			sps = append(sps, IdPFcWrapper{
				Override:  fc.ChannelA.GetOverrideProviderSetup(),
				Preferred: false,
				SP:        fc.GetName(),
				Fc:        &fc,
			})
		}
	}

	return sps

}

func (c *IdPFcWrapper) Name() string {
	return c.Fc.GetName()
}

func (c *IdPFcWrapper) ChannelName() string {
	return c.Fc.ChannelA.GetName()
}

func (c *IdPFcWrapper) Location() string {
	l := c.Fc.ChannelA.GetLocation()
	return cli.LocationToStr(&l)
}

func (c *IdPFcWrapper) Metadata() string {
	return c.Location() + "/SAML2/MD"
}

func (c *IdPFcWrapper) ConnectionName() string {
	return c.Fc.GetName()
}

func (c *IdPFcWrapper) OverrideProvider() bool {

	return c.Fc.ChannelA.GetOverrideProviderSetup()
}

func (c *IdPFcWrapper) SignatureHash() string {
	idpchannel, err := c.Fc.GetSPChannel()
	if err != nil {
		return err.Error()
	}

	s := idpchannel.GetSignatureHash()
	if s == "" {
		return "SHA256"
	}
	return s
}

func (c *IdPFcWrapper) MessageTTL() int32 {
	idpchannel, err := c.Fc.GetSPChannel()
	if err != nil {
		return 1
	}
	return idpchannel.GetMessageTtl()
}

func (c *IdPFcWrapper) MessageTTLTolerance() int32 {
	idpchannel, err := c.Fc.GetSPChannel()
	if err != nil {
		return 1
	}
	return idpchannel.GetMessageTtlTolerance()
}

func (c *IdPFcWrapper) WantAuthnSigned() bool {
	spChannel, _ := c.Fc.GetSPChannel()
	return spChannel.GetWantAuthnRequestsSigned()
}

func (c *IdPFcWrapper) WantReqSigned() bool {
	return false
}

func (c *IdPFcWrapper) SignReq() bool {
	return true
}

func (c *IdPFcWrapper) EncryptAssertion() bool {
	spChannel, _ := c.Fc.GetSPChannel()
	return spChannel.GetEncryptAssertion()
}

func (c *IdPFcWrapper) EncryptAlgorithm() string {
	spChannel, _ := c.Fc.GetSPChannel()
	return spChannel.GetEncryptAssertionAlgorithm()
}

func (c *IdPFcWrapper) Bindings() string {
	// concatenate c.p.GetActiveBindings() as a single string
	return strings.Join(c.Fc.ChannelA.GetActiveBindings(), ", ")
}

func (c *IdPFcWrapper) HttpPostBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_HTTP_POST")
}

func (c *IdPFcWrapper) HttpRedirectBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_HTTP_REDIRECT")
}

func (c *IdPFcWrapper) SoapBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_SOAP")
}

func (c *IdPFcWrapper) ArtifactBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_ARTIFACT")
}

func (c *IdPFcWrapper) LocalBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_LOCAL")
}

func (c *IdPFcWrapper) HasBinding(b string) bool {
	for _, binding := range c.Fc.ChannelA.GetActiveBindings() {
		if binding == b {
			return true
		}
	}
	return false
}
