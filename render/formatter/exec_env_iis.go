package formatter

import (
	"strconv"

	api "github.com/atricore/josso-api-go"
)

const (
	iisTFFormat = `resource "iamtf_execenv_iis" "{{.Name}}" {
	name = "{{.Name}}"
}`
	WindowsIISPrettyFormat = `
Windows IIS Execution Environment

General 
	Name:                           {{.Name}}
	Id:                             {{.ID}}
	Description:                    {{.DisplayName}}
	Location:                       {{.Location}}`
)

type ExecEnvWindowsIISWrapper struct {
	HeaderContext
	trunc bool
	p     *api.WindowsIISExecutionEnvironmentDTO
}

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewWindowsIISFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultExecEnvTableFormat
		}
	case TFFormatKey:
		return iisTFFormat
	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return WindowsIISPrettyFormat
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

func WindowsIISExecEnvWrite(ctx ExecEnvContext, iis []api.WindowsIISExecutionEnvironmentDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return WindowsIISFormat(ctx, iis, format)
	}
	return ctx.Write(newLdapWrapper(), render)

}

func WindowsIISFormat(ctx ExecEnvContext, execEnvWindowsIISs []api.WindowsIISExecutionEnvironmentDTO, format func(subContext SubContext) error) error {
	for _, execEnvWindowsIIS := range execEnvWindowsIISs {
		c := ExecEnvWindowsIISWrapper{
			p:     &execEnvWindowsIIS,
			trunc: false,
		}
		if err := format(&c); err != nil {
			return err
		}
	}
	return nil
}

func newWindowsIISWrapper() *ExecEnvWindowsIISWrapper {
	WindowsIISWrapper := ExecEnvWindowsIISWrapper{}
	WindowsIISWrapper.Header = SubHeaderContext{
		"Name": nameHeader,
		"Type": typeHeader,
	}
	return &WindowsIISWrapper
}

func (c *ExecEnvWindowsIISWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *ExecEnvWindowsIISWrapper) ID() string {

	id := strconv.FormatInt(c.p.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

func (c *ExecEnvWindowsIISWrapper) Name() string {
	return c.p.GetName()
}

func (c *ExecEnvWindowsIISWrapper) DisplayName() string {
	return c.p.GetDisplayName()
}

func (c *ExecEnvWindowsIISWrapper) Location() string {
	return c.p.GetLocation()
}
