package formatter

import (
	api "github.com/atricore/josso-api-go"
)

const (
	defaultProviderTableFormat = "table {{.Name}}\t{{.Type}}\t{{.Location}}"
)

type ProviderFormatter struct {
	PType     string
	PFormat   func(source string, quiet bool) Format
	PWriter   func(ctx ProviderContext, providers []api.ProviderContainerDTO) error
	PResolver func(n string) (interface{}, error)
}

type ProviderContext struct {
	Context
}

type providerContainerWrapper struct {
	HeaderContext
	trunc bool
	p     *api.ProviderContainerDTO
}

type providerWrapper struct {
	HeaderContext
	trunc bool
	p     *api.FederatedProviderDTO
}

func ProviderWrite(ctx ProviderContext, providers []api.FederatedProviderDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return providerFormat(ctx, providers, format)
	}
	return ctx.Write(newProviderContainerWrapper(), render)

}

func providerFormat(ctx ProviderContext, providers []api.FederatedProviderDTO, format func(subContext SubContext) error) error {
	for _, provider := range providers {
		formatted := []*providerWrapper{}

		c := providerWrapper{
			p:     &provider,
			trunc: false,
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
		formatted := []*providerContainerWrapper{}

		c := providerContainerWrapper{
			p:     &provider,
			trunc: false,
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

func newProviderContainerWrapper() *providerContainerWrapper {
	providerWrapper := providerContainerWrapper{}
	providerWrapper.Header = SubHeaderContext{
		"Name":     nameHeader,
		"Type":     typeHeader,
		"Location": locationHeader,
	}
	return &providerWrapper
}

func (c *providerContainerWrapper) Name() string {
	return c.p.GetName()
}

func (c *providerContainerWrapper) Type() string {
	return c.p.GetType()
}

func (c *providerContainerWrapper) Location() string {
	return c.p.GetLocation()
}
