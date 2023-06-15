package formatter

import api "github.com/atricore/josso-api-go"

/**
* Any wrapper that has a CustomClassDTO must define an Extension() method that returns a CustomClassWrapper
 */

// Insert this snippet into your main template
const (
	extensionTFFormat = `{{- if .Extension.HasExtension }}
    extension {
		fqcn = "{{.Extension.FCQN}}"
		osgi_filter = "{{.Extension.OsgiFilter}}"
		type = "{{.Extension.Type}}"
		{{ range $props := .Extension.CustomClassProperties}}
		property {
			name = "{{$props.Name}}"
			value = "{{$props.Value}}"
		}
		{{- end }}

	}
{{- end }}`
	extensionFormat = `
	{{- if .Extension.HasExtension }}
	Extension
    FCQN:        {{.Extension.FCQN}}
    Osgi Filter: {{.Extension.OsgiFilter}}
    Type:        {{.Extension.Type}}
   
    Properties {{ range $props := .Extension.CustomClassProperties}}
                Name:   {{$props.Name}}
                Value:  {{$props.Value}}
    {{ end }}{{- end }}
	{{- if not .Extension.HasExtension }}
	Extension: not configured
	{{- end }}
`
)

type CustomClassWrapper struct {
	cc *api.CustomClassDTO
}

func (c *CustomClassWrapper) HasExtension() bool {
	val, ok := c.cc.GetFqcnOk()
	return ok && *val != ""
}

func (c *CustomClassWrapper) FCQN() string {
	return c.cc.GetFqcn()
}

func (c *CustomClassWrapper) OsgiFilter() string {
	return c.cc.GetOsgiFilter()
}

func (c *CustomClassWrapper) CustomClassProperties() []CustomClassPropsWrapper {

	var ccpWrappers []CustomClassPropsWrapper

	if c.cc.GetProperties() == nil {
		return ccpWrappers
	}
	ccp := c.cc.Properties
	for i := range ccp {
		ccpWrappers = append(ccpWrappers, CustomClassPropsWrapper{props: &c.cc.GetProperties()[i]})
	}
	return ccpWrappers
}

func (c *CustomClassWrapper) Type() string {
	if c.cc.GetOsgiService() {
		return "SERVICE"
	} else {
		return "INSTANCE"
	}
}

type CustomClassPropsWrapper struct {
	props *api.CustomClassPropertyDTO
}

func (c *CustomClassProp) Name() string {
	return c.props.GetName()
}

func (c *CustomClassProp) Value() string {
	return c.props.GetValue()
}
