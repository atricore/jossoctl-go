package formatter

import (
	api "github.com/atricore/josso-api-go"
)

const (
	defaultIdSourceTableFormat = "table {{.Name}}\t{{.Type}}"
	definitionFormat           = `    Definition
    FCQN:        {{.FCQN}}
    Osgi Filter: {{.Osgi_filter}}	
    Type:        {{.Type}}
	{{- if .Osgi_filter }}
    Properties {{ range $props := .CustomClassProperties}}
                Name:   {{$props.Name}}
                Value:  {{$props.Value}}
	{{ end }}{{ end }}
`
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

type idSourceContainerWrapper struct {
	HeaderContext
	trunc bool
	p     *api.IdSourceContainerDTO
}

type idSourceWrapper struct {
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

func idsourceFormat(ctx IdSourceContext, idSources []api.IdentitySourceDTO, format func(subContext SubContext) error) error {
	for _, idSource := range idSources {
		c := idSourceWrapper{
			p:     &idSource,
			trunc: false,
		}
		if err := format(&c); err != nil {
			return err
		}
	}
	return nil
}

func IdSourceContainerWrite(ctx IdSourceContext, idSources []api.IdSourceContainerDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return idSourceContainerFormat(ctx, idSources, format)
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
`
		}
	}

	format := Format(source)
	return format
}

func idSourceContainerFormat(ctx IdSourceContext, idSources []api.IdSourceContainerDTO, format func(subContext SubContext) error) error {
	for _, idSource := range idSources {

		c := idSourceContainerWrapper{
			p:     &idSource,
			trunc: false,
		}
		if err := format(&c); err != nil {
			return err
		}
	}
	return nil
}

func newIdSourceContainerWrapper() *idSourceContainerWrapper {
	idsourceWrapper := idSourceContainerWrapper{}
	idsourceWrapper.Header = SubHeaderContext{
		"Name": nameHeader,
		"Type": typeHeader,
	}
	return &idsourceWrapper
}

func (c *idSourceContainerWrapper) Name() string {
	return c.p.GetName()
}

func (c *idSourceContainerWrapper) Type() string {
	return c.p.GetType()
}
