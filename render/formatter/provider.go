package formatter

import (
	api "github.com/atricore/josso-api-go"
	clicmd "github.com/atricore/josso-cli-go/cli"
	cli "github.com/atricore/josso-sdk-go"
)

const (
	defaultTFProviderFormat    = `Name:		{{.Name}} NOT SUPPORTED!`
	defaultProviderTableFormat = "table {{.Name}}\t{{.Type}}\t{{.Location}}"
	defaultProviderFormat      = `Name:		{{.Name}}
Location:	{{.Location}}`
)

type ProviderFormatter struct {
	PType     string
	PFormat   func(source string, quiet bool) Format
	PWriter   func(ctx ProviderContext, id_or_name string, providers []api.ProviderContainerDTO) error
	PResolver func(n string) (interface{}, error)
}

type ProviderContext struct {
	Client  clicmd.Cli
	IdaName string
	Context
}

type providerContainerWrapper struct {
	HeaderContext
	trunc   bool
	idaName string
	p       *api.ProviderContainerDTO
}

func (c *providerContainerWrapper) Name() string {
	return c.p.GetName()
}

func (c *providerContainerWrapper) Type() string {
	return c.p.GetType()
}

func (c *providerContainerWrapper) Location() string {
	// convert *string to string
	if c.p.Location == nil {
		return ""
	} else {
		return *c.p.Location
	}
}

type providerWrapper struct {
	HeaderContext
	trunc bool
	p     *api.FederatedProviderDTO
}

func (c *providerWrapper) Name() string {
	return c.p.GetName()
}
func (c *providerWrapper) Location() string {
	return cli.LocationToStr(c.p.Location)
}

func ProviderWrite(ctx ProviderContext, providers []api.FederatedProviderDTO) error {

	render := func(format func(subContext SubContext) error) error {

		for _, provider := range providers {
			c := providerWrapper{p: &provider}
			if err := format(&c); err != nil {
				return err
			}
		}
		return nil
	}
	return ctx.Write(newProviderContainerWrapper(), render)

}

func ProviderContainerWrite(ctx ProviderContext, providers []api.ProviderContainerDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return providerContainerFormat(ctx, providers, format)
	}
	return ctx.Write(newProviderContainerWrapper(), render)
}

func NewProviderContainerFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultProviderTableFormat
		}
	case TFFormatKey:
		return defaultTFProviderFormat
	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultProviderFormat
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

func providerContainerFormat(ctx ProviderContext, providers []api.ProviderContainerDTO, format func(subContext SubContext) error) error {
	for _, provider := range providers {
		c := providerContainerWrapper{
			p:     &provider,
			trunc: false,
		}
		if err := format(&c); err != nil {
			return err
		}

	}
	return nil
}

func newProviderContainerWrapper() *providerContainerWrapper {
	providerWrapper := providerContainerWrapper{}
	providerWrapper.Header = SubHeaderContext{
		"Name":     nameHeader,
		"Type":     typeHeader,
		"Location": locationHeader,
	}
	return &providerWrapper
}

func mapSaml2SignatureToTF(signature string) string {
	if signature == "" {
		return "SHA256"
	}

	return signature
}

func mapSaml2EncryptionToTF(encryption string) string {

	// "NONE", "AES-128", "AES-256", "AES-3DES"

	// disabled
	// "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
	// "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
	// "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";

	switch encryption {
	case "disabled":
		return "NONE"
	case "http://www.w3.org/2001/04/xmlenc#aes128-cbc":
		return "AES128"
	case "http://www.w3.org/2001/04/xmlenc#aes256-cbc":
		return "AES256"
	case "http://www.w3.org/2001/04/xmlenc#tripledes-cbc":
		return "AES3DES"
	default:
		return "NONE"
	}
}
