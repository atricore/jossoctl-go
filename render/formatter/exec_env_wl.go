package formatter

import (
	"strconv"

	api "github.com/atricore/josso-api-go"
)

const (
	weblogicTFFormat = `resource "iamtf_execenv_weblogic" "{{.Name}}" {
    ida = "{{.ApplianceName}}"
	name = "{{.Name}}"
}`
	WeblogicPrettyFormat = `
Weblogic Execution Environment

General 
	Name:                           {{.Name}}
	Id:                             {{.ID}}
	Description:                    {{.DisplayName}}
	Location:                       {{.Location}}`
)

type ExecEnvWeblogicWrapper struct {
	HeaderContext
	trunc bool
	idaName string
	p     *api.WeblogicExecutionEnvironmentDTO
}

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewWeblogicFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultExecEnvTableFormat
		}
	case TFFormatKey:
		return weblogicTFFormat
	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return WeblogicPrettyFormat
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

func WeblogicExecEnvWrite(ctx ExecEnvContext, weblogic []api.WeblogicExecutionEnvironmentDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return WeblogicFormat(ctx, weblogic, format)
	}
	return ctx.Write(newLdapWrapper(), render)

}

func WeblogicFormat(ctx ExecEnvContext, execEnvWeblogics []api.WeblogicExecutionEnvironmentDTO, format func(subContext SubContext) error) error {
	for _, execEnvWeblogic := range execEnvWeblogics {
		c := ExecEnvWeblogicWrapper{
			idaName: ctx.IdaName,
			p:       &execEnvWeblogic,
			trunc:   false,
		}
		if err := format(&c); err != nil {
			return err
		}
	}
	return nil
}

func newWeblogicWrapper() *ExecEnvWeblogicWrapper {
	WeblogicWrapper := ExecEnvWeblogicWrapper{}
	WeblogicWrapper.Header = SubHeaderContext{
		"Name": nameHeader,
		"Type": typeHeader,
	}
	return &WeblogicWrapper
}

func (c *ExecEnvWeblogicWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *ExecEnvWeblogicWrapper) ID() string {

	id := strconv.FormatInt(c.p.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

func (c *ExecEnvWeblogicWrapper) ApplianceName() string {
	return c.idaName
}

func (c *ExecEnvWeblogicWrapper) Name() string {
	return c.p.GetName()
}

func (c *ExecEnvWeblogicWrapper) DisplayName() string {
	return c.p.GetDisplayName()
}

func (c *ExecEnvWeblogicWrapper) Location() string {
	return c.p.GetLocation()
}
