package formatter

import (
	api "github.com/atricore/josso-api-go"
)

const (
	defaultIdSourceTableFormat = "table {{.Name}}\t{{.Type}}"
)

type IdSourceFormatter struct {
	IdSourceType     string
	IdSourceFormat   func(source string, quiet bool) Format
	IdSourceWriter   func(ctx IdSourceContext, idsources []api.IdSourceContainerDTO) error
	IdSourceResolver func(n string) (interface{}, error)
}

type IdSourceContext struct {
	Context
}

type idsourceContainerWrapper struct {
	HeaderContext
	trunc bool
	p     *api.IdSourceContainerDTO
}

type idsourceWrapper struct {
	HeaderContext
	trunc bool
	p     *api.IdentitySourceDTO
}

func IdSourceWrite(ctx IdSourceContext, idsources []api.IdentitySourceDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return idsourceFormat(ctx, idsources, format)
	}
	return ctx.Write(newIdSourceContainerWrapper(), render)

}

func idsourceFormat(ctx IdSourceContext, idsources []api.IdentitySourceDTO, format func(subContext SubContext) error) error {
	for _, idsource := range idsources {
		formatted := []*idsourceWrapper{}

		c := idsourceWrapper{
			p:     &idsource,
			trunc: false,
		}

		formatted = append(formatted, &c)

		for _, idsourceCtx := range formatted {
			if err := format(idsourceCtx); err != nil {
				return err
			}
		}
	}
	return nil
}

func IdSourceContainerWrite(ctx IdSourceContext, idsources []api.IdSourceContainerDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return idsourceContainerFormat(ctx, idsources, format)
	}
	return ctx.Write(newIdSourceContainerWrapper(), render)

}

func NewIdSourceContainerFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultIdSourceTableFormat
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

func idsourceContainerFormat(ctx IdSourceContext, idsources []api.IdSourceContainerDTO, format func(subContext SubContext) error) error {
	for _, idsource := range idsources {
		formatted := []*idsourceContainerWrapper{}

		c := idsourceContainerWrapper{
			p:     &idsource,
			trunc: false,
		}

		formatted = append(formatted, &c)

		for _, idsourceCtx := range formatted {
			if err := format(idsourceCtx); err != nil {
				return err
			}
		}
	}
	return nil
}

func newIdSourceContainerWrapper() *idsourceContainerWrapper {
	idsourceWrapper := idsourceContainerWrapper{}
	idsourceWrapper.Header = SubHeaderContext{
		"Name": nameHeader,
		"Type": typeHeader,
	}
	return &idsourceWrapper
}

func (c *idsourceContainerWrapper) Name() string {
	return c.p.GetName()
}

func (c *idsourceContainerWrapper) Type() string {
	return c.p.GetType()
}
