package formatter

import (
	"strconv"

	api "github.com/atricore/josso-api-go"
)

const (
	phpTFFormat = `resource "iamtf_execenv_php" "{{.Name}}" {
	ida = "{{.ApplianceName}}"
	name = "{{.Name}}"
}`
	PHPPrettyFormat = `
PHP Execution Environment

General 
	Name:                           {{.Name}}
	Id:                             {{.ID}}
	Description:                    {{.DisplayName}}
	Location:                       {{.Location}}`
)

type ExecEnvPHPWrapper struct {
	HeaderContext
	trunc   bool
	idaName string
	p       *api.PHPExecutionEnvironmentDTO
}

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewPHPFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultExecEnvTableFormat
		}
	case TFFormatKey:
		return phpTFFormat
	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return PHPPrettyFormat
		}
	case RawFormatKey:
		switch {
		case quiet:
			return `nameabc: {{.Name}}`
		default:
			return `nameavc: {{.Name}}
type: {{.Type}}
`
		}
	}

	format := Format(source)
	return format
}

func PHPExecEnvWrite(ctx ExecEnvContext, php []api.PHPExecutionEnvironmentDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return PHPFormat(ctx, php, format)
	}
	return ctx.Write(newLdapWrapper(), render)

}

func PHPFormat(ctx ExecEnvContext, execEnvPHPs []api.PHPExecutionEnvironmentDTO, format func(subContext SubContext) error) error {
	for _, execEnvPHP := range execEnvPHPs {
		c := ExecEnvPHPWrapper{
			idaName: ctx.IdaName,
			p:       &execEnvPHP,
			trunc:   false,
		}
		if err := format(&c); err != nil {
			return err
		}
	}
	return nil
}

func newPHPWrapper() *ExecEnvPHPWrapper {
	PHPWrapper := ExecEnvPHPWrapper{}
	PHPWrapper.Header = SubHeaderContext{
		"Name": nameHeader,
		"Type": typeHeader,
	}
	return &PHPWrapper
}

func (c *ExecEnvPHPWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *ExecEnvPHPWrapper) ID() string {

	id := strconv.FormatInt(c.p.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

func (c *ExecEnvPHPWrapper) ApplianceName() string {
	return c.idaName
}

func (c *ExecEnvPHPWrapper) Name() string {
	return c.p.GetName()
}

func (c *ExecEnvPHPWrapper) DisplayName() string {
	return c.p.GetDisplayName()
}

func (c *ExecEnvPHPWrapper) Location() string {
	return c.p.GetLocation()
}
