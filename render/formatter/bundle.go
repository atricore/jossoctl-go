package formatter

import (
	api "github.com/atricore/josso-api-go"
	clicmd "github.com/atricore/josso-cli-go/cli"
)

const (
	defaultOSGiBundleTableFormat = "{{.Bundle.Id}} {{.Bundle.State}}\t{{.Version}}\t{{.Bundle.SymbolicName}}"
)

type OSGiBundleFormatter struct {
	Type     string
	Format   func(source string, quiet bool) Format
	Writer   func(ctx OSGiBundleContext, idaName string, idsources []api.BundleDescr) error
	Resolver func(n string) (interface{}, error)
}

type OSGiBundleContext struct {
	IdaName string
	Client  clicmd.Cli
	Context
}

type osgiBundleContainerWrapper struct {
	HeaderContext
	trunc bool
	p     *api.BundleDescr
}

type osgiBundleWrapper struct {
	HeaderContext
	trunc bool
	p     *api.BundleDescr
}

func OSGiBundleWrite(ctx OSGiBundleContext, idsources []api.BundleDescr) error {
	render := func(format func(subContext SubContext) error) error {
		return osgiBundleFormat(ctx, idsources, format)
	}
	return ctx.Write(newOSGiBundleContainerWrapper(), render)

}

func osgiBundleFormat(ctx OSGiBundleContext, osgiBundles []api.BundleDescr, format func(subContext SubContext) error) error {
	for _, osgiBundle := range osgiBundles {
		c := osgiBundleWrapper{
			p:     &osgiBundle,
			trunc: false,
		}
		if err := format(&c); err != nil {
			return err
		}
	}
	return nil
}

func OSGiBundleContainerWrite(ctx OSGiBundleContext, osgiBundles []api.BundleDescr) error {
	render := func(format func(subContext SubContext) error) error {
		return osgiBundleContainerFormat(ctx, osgiBundles, format)
	}
	return ctx.Write(newOSGiBundleContainerWrapper(), render)

}

func NewOSGiBundleContainerFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultOSGiBundleTableFormat
		}
	case RawFormatKey:
		switch {
		case quiet:
			return `name: {{.Name}}`
		default:
			return `{{.Bundle.Id}}\t{{.Bundle.Location}}`
		}
	}

	format := Format(source)
	return format
}

func osgiBundleContainerFormat(ctx OSGiBundleContext, osgiBundles []api.BundleDescr, format func(subContext SubContext) error) error {
	for _, osgiBundle := range osgiBundles {

		c := osgiBundleContainerWrapper{
			p:     &osgiBundle,
			trunc: false,
		}
		if err := format(&c); err != nil {
			return err
		}
	}
	return nil
}

func newOSGiBundleContainerWrapper() *osgiBundleContainerWrapper {
	idsourceWrapper := osgiBundleContainerWrapper{}
	idsourceWrapper.Header = SubHeaderContext{
		"Name": nameHeader,
		"Type": typeHeader,
	}
	return &idsourceWrapper
}

func (c *osgiBundleWrapper) Name() string {
	return c.p.GetName()
}

func (c *osgiBundleWrapper) Version() string {
	return LeftPad(c.p.GetVersion(), " ", 20)
}

func (c *osgiBundleWrapper) Bundle() *api.BundleDescr {
	return c.p
}
