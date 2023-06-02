package formatter

import (
	api "github.com/atricore/josso-api-go"
	clicmd "github.com/atricore/josso-cli-go/cli"
)

const (
	defaultExecEnvTableFormat = "table {{.Name}}\t{{.Type}}"
)

type ExecEnvFormatter struct {
	ExecEnvType     string
	ExecEnvFormat   func(source string, quiet bool) Format
	ExecEnvWriter   func(ctx ExecEnvContext, id_or_name string, execEnv []api.ExecEnvContainerDTO) error
	ExecEnvResolver func(n string) (interface{}, error)
}

type ExecEnvContext struct {
	Client clicmd.Cli
	Context
}

type ExecEnvContainerWrapper struct {
	HeaderContext
	trunc bool
	p     *api.ExecEnvContainerDTO
}

type ExecEnvWrapper struct {
	HeaderContext
	trunc bool
	p     *api.ExecutionEnvironmentDTO
}

func ExecEnvWrite(ctx ExecEnvContext, execEnvs []api.ExecutionEnvironmentDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return execEnvFormat(ctx, execEnvs, format)
	}
	return ctx.Write(newExecEnvContainerWrapper(), render)

}

func execEnvFormat(ctx ExecEnvContext, execEnvs []api.ExecutionEnvironmentDTO, format func(subContext SubContext) error) error {
	for _, execEnv := range execEnvs {
		c := ExecEnvWrapper{
			p:     &execEnv,
			trunc: false,
		}
		if err := format(&c); err != nil {
			return err
		}
	}
	return nil
}

func ExecEnvContainerWrite(ctx ExecEnvContext, execEnvs []api.ExecEnvContainerDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return execEnvContainerFormat(ctx, execEnvs, format)
	}
	return ctx.Write(newExecEnvContainerWrapper(), render)

}

func NewExecEnvContainerFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultExecEnvTableFormat
		}
	case TFFormatKey:
		return defaultExecEnvTableFormat
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

func execEnvContainerFormat(ctx ExecEnvContext, execEnvs []api.ExecEnvContainerDTO, format func(subContext SubContext) error) error {
	for _, execEnv := range execEnvs {

		c := ExecEnvContainerWrapper{
			p:     &execEnv,
			trunc: false,
		}
		if err := format(&c); err != nil {
			return err
		}
	}
	return nil
}

func newExecEnvContainerWrapper() *ExecEnvContainerWrapper {
	execEnvWrapper := ExecEnvContainerWrapper{}
	execEnvWrapper.Header = SubHeaderContext{
		"Name": nameHeader,
		"Type": typeHeader,
	}
	return &execEnvWrapper
}

func (c *ExecEnvContainerWrapper) Name() string {
	return c.p.GetName()
}

func (c *ExecEnvContainerWrapper) Type() string {
	return c.p.GetType()
}
