package formatter

import (
	"strings"

	api "github.com/atricore/josso-api-go"
	cli "github.com/atricore/josso-sdk-go"
)

/**
 * Wrap a connection to a service provider (FC -> channelB as IDPChannel)
 */
type SPFcWrapper struct {
	Preferred bool
	IdP       string
	Fc        *api.FederatedConnectionDTO
}

// Federated Connection
func (c *SPFcWrapper) ChannelName() string {
	return c.Fc.ChannelB.GetName()
}

func (c *SPFcWrapper) AccountLinkage() string {
	idpChannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}
	return idpChannel.AccountLinkagePolicy.GetName()
}

func (c *SPFcWrapper) IdentityMapping() string {
	idpChannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}
	return idpChannel.IdentityMappingPolicy.GetName()
}

func (c *SPFcWrapper) OverrideProvider() bool {
	return c.Fc.ChannelB.GetOverrideProviderSetup()
}

func (c *SPFcWrapper) ConnectionName() string {
	return c.Fc.GetName()
}

func (c *SPFcWrapper) SignAuthenticationRequests() bool {
	idpChannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return false
	}
	return idpChannel.GetSignAuthenticationRequests()
}

func (c *SPFcWrapper) WantAssertionSigned() bool {
	idpChannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return false
	}
	return idpChannel.GetWantAssertionSigned()
}

func (c *SPFcWrapper) Bindings() string {
	// concatenate c.p.GetActiveBindings() as a single string
	return strings.Join(c.Fc.ChannelB.GetActiveBindings(), ", ")
}

func (c *SPFcWrapper) HttpPostBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_HTTP_POST")
}

func (c *SPFcWrapper) HttpRedirectBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_HTTP_REDIRECT")
}

func (c *SPFcWrapper) SoapBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_SOAP")
}

func (c *SPFcWrapper) ArtifactBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_ARTIFACT")
}

func (c *SPFcWrapper) LocalBinding() bool {
	// return true if c.Provider.GetActiveBindings() containes "HTTP_POST"
	return c.HasBinding("SAMLR2_LOCAL")
}

func (c *SPFcWrapper) HasBinding(b string) bool {
	for _, binding := range c.Fc.ChannelB.GetActiveBindings() {
		if binding == b {
			return true
		}
	}
	return false
}

func (c *SPFcWrapper) Location() string {
	l := c.Fc.ChannelB.GetLocation()
	return cli.LocationToStr(&l)
}

func (c *SPFcWrapper) Metadata() string {
	return c.Location() + "/SAML2/MD"
}

func (c *SPFcWrapper) IsPreferred() bool {
	idpchannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return false
	}
	return idpchannel.GetPreferred()
}

func (c *SPFcWrapper) SignatureHash() string {

	idpchannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}

	return mapSaml2SignatureToTF(idpchannel.GetSignatureHash())
}

func (c *SPFcWrapper) MessageTTL() int32 {

	idpchannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return 0
	}

	return idpchannel.GetMessageTtl()
}

func (c *SPFcWrapper) MessageTTLTolerance() int32 {

	idpchannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return 0
	}

	return idpchannel.GetMessageTtlTolerance()
}

func (c *SPFcWrapper) EnableProxyExtension() bool {

	idpchannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return false
	}

	return idpchannel.GetEnableProxyExtension()
}

func (c *SPFcWrapper) Name() string {
	return c.Fc.GetName()
}

func (c *SPFcWrapper) AccountLinkagePolicy() string {
	idpchannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}
	return idpchannel.AccountLinkagePolicy.GetLinkEmitterType()
}

func (c *SPFcWrapper) IdentityMappingPolicy() string {
	idpchannel, err := c.Fc.GetIDPChannel()
	if err != nil {
		return err.Error()
	}
	return idpchannel.IdentityMappingPolicy.GetMappingType()
}

func (c *SPFcWrapper) WantReqSigned() bool {
	return false
}

func (c *SPFcWrapper) SignReq() bool {
	return true
}
