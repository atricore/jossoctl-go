package formatter

import (
	"strconv"

	api "github.com/atricore/josso-api-go"
)

const (
	tomcatTFFormat = `resource "iamtf_execenv_tomcat" "{{.Name}}" {
    ida = "{{.ApplianceName}}"
	name = "{{.Name}}"
}`
	TomcatPrettyFormat = `
Tomcat Execution Environment

General 
	Name:                           {{.Name}}
	Id:                             {{.ID}}
	Description:                    {{.DisplayName}}
	Location:                       {{.Location}}`
)

type ExecEnvTomcatWrapper struct {
	HeaderContext
	trunc bool
	idaName string
	p     *api.TomcatExecutionEnvironmentDTO
}

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewTomcatFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultExecEnvTableFormat
		}
	case TFFormatKey:
		return tomcatTFFormat
	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return TomcatPrettyFormat
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

func TomcatExecEnvWrite(ctx ExecEnvContext, tomcat []api.TomcatExecutionEnvironmentDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return TomcatFormat(ctx, tomcat, format)
	}
	return ctx.Write(newLdapWrapper(), render)

}

func TomcatFormat(ctx ExecEnvContext, execEnvTomcats []api.TomcatExecutionEnvironmentDTO, format func(subContext SubContext) error) error {
	for _, execEnvTomcat := range execEnvTomcats {
		c := ExecEnvTomcatWrapper{
			idaName: ctx.IdaName,
			p:     &execEnvTomcat,
			trunc: false,
		}
		if err := format(&c); err != nil {
			return err
		}
	}
	return nil
}

func newTomcatWrapper() *ExecEnvTomcatWrapper {
	TomcatWrapper := ExecEnvTomcatWrapper{}
	TomcatWrapper.Header = SubHeaderContext{
		"Name": nameHeader,
		"Type": typeHeader,
	}
	return &TomcatWrapper
}

func (c *ExecEnvTomcatWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *ExecEnvTomcatWrapper) ID() string {

	id := strconv.FormatInt(c.p.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

func (c *ExecEnvTomcatWrapper) ApplianceName() string {
	return c.idaName
}


func (c *ExecEnvTomcatWrapper) Name() string {
	return c.p.GetName()
}

func (c *ExecEnvTomcatWrapper) DisplayName() string {
	return c.p.GetDisplayName()
}

func (c *ExecEnvTomcatWrapper) Location() string {
	return c.p.GetLocation()
}
