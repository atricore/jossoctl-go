package formatter

import (
	"sort"
	"strconv"
	"strings"
	"time"

	api "github.com/atricore/josso-api-go"
	cmdcli "github.com/atricore/josso-cli-go/cli"
	cli "github.com/atricore/josso-sdk-go"
)

const (
	defaultApplianceTableFormat = "table {{.ID}}\t{{.Name}}\t{{.State}}\t{{.Location}}"

	defaultApplianceTFFormat = `resource "iamtf_identity_appliance" "{{.Name}}" {
    name        = "{{.Name}}"
    location    = "{{.Location}}"
	namespace   = "{{.Namespace}}"
	description = "{{.Description}}"
	{{- if .HasBundles}}
	bundles     = [{{.Bundles}}]
	{{- end}}
	branding    = {{.Branding}}
}`

	defaultAppliancePrettyFormat = `ID:          {{.ID}}
Name:        {{.Name}}
{{- if .Description }}
Description: {{.Description}}
{{- end }}
Location:    {{.Location}}
Namespace:   {{.Namespace}}
Revision:    {{.Revision}}
Bundles:     {{.Bundles}}

Id Sources:  {{.IdSourcesCount}} {{range .IdSources}}
             {{.}},{{- end}}

Providers:   {{.ProvidersCount}} {{range .Providers}}
             {{.}},{{- end}}

Exec. Envs.: {{.ExecEnvsCount}} {{range .ExecEnvs}}
             {{.}},{{- end}}

{{- if .IsDeployed }}
Deployment:
  Time:      {{.DeploymentType}}
  Revision:  {{.DeployedRevision}}
{{- end }}

`

	applianceIDHeader = "ID"
	nameHeader        = "NAME"
	typeHeader        = "TYPE"
	namespaceHeader   = "NS"
	locationHeader    = "LOCATION"
	stateHeader       = "STATE"
)

// ApplianceContext contains appliance specific information required by the formatter, encapsulate a Context struct.
type ApplianceContext struct {
	Client cmdcli.Cli
	Context
}

type applianceWrapper struct {
	HeaderContext
	trunc bool
	a     api.IdentityApplianceDTO
	c     api.IdentityApplianceContainerDTO
}

// NewApplianceFormat returns a format for rendering an ApplianceContext
func NewApplianceFormat(source string, quiet bool) Format {
	switch source {
	case TableFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultApplianceTableFormat
		}
	case TFFormatKey:
		return defaultApplianceTFFormat

	case PrettyFormatKey:
		switch {
		case quiet:
			return DefaultQuietFormat
		default:
			return defaultAppliancePrettyFormat
		}
	case RawFormatKey:
		switch {
		case quiet:
			return `appliance_id: {{.ID}}`
		default:
			return `appliance_id: {{.ID}}
name: {{.Name}}
state: {{.State}}
location: {{.Location}}
`
		}
	}

	format := Format(source)
	return format
}

// ApplianceWrite writes the formatter appliances using the ApplianceContext
func ApplianceWrite(ctx ApplianceContext, appliances []api.IdentityApplianceContainerDTO) error {
	render := func(format func(subContext SubContext) error) error {
		return applianceFormat(ctx, appliances, format)
	}
	return ctx.Write(newApplianceWrapper(), render)
}

func applianceFormat(ctx ApplianceContext, appliances []api.IdentityApplianceContainerDTO, format func(subContext SubContext) error) error {
	for _, appliance := range appliances {
		formatted := []*applianceWrapper{}

		c := applianceWrapper{
			a:     appliance.GetAppliance(),
			c:     appliance,
			trunc: false,
		}

		formatted = append(formatted, &c)

		for _, applianceCtx := range formatted {
			if err := format(applianceCtx); err != nil {
				return err
			}
		}
	}
	return nil
}

func newApplianceWrapper() *applianceWrapper {
	applianceCtx := applianceWrapper{}
	applianceCtx.Header = SubHeaderContext{
		"ID":        applianceIDHeader,
		"Name":      nameHeader,
		"Namespace": namespaceHeader,
		"Location":  locationHeader,
		"State":     stateHeader,
	}
	return &applianceCtx
}

func (c *applianceWrapper) MarshalJSON() ([]byte, error) {
	return MarshalJSON(c)
}

func (c *applianceWrapper) ID() string {

	id := strconv.FormatInt(c.a.GetId(), 10)
	if c.trunc {
		return TruncateID(id, 6)
	}
	return id
}

func (c *applianceWrapper) Name() string {
	return c.a.GetName()
}

func (c *applianceWrapper) Namespace() string {
	return c.a.GetNamespace()
}

func (c *applianceWrapper) State() string {
	return c.a.GetState()
}

func (c *applianceWrapper) Location() string {
	return cli.LocationToStr(c.a.GetIdApplianceDefinition().Location)
}

func (c *applianceWrapper) Description() string {
	d := c.a.GetDescription()
	if d == "" {
		d = c.a.GetDisplayName()
	}

	return d
}

func (c *applianceWrapper) Revision() int32 {
	d := c.a.GetIdApplianceDefinition()
	return d.GetRevision()
}

func (c *applianceWrapper) DeployedRevision() int32 {
	d := c.a.GetIdApplianceDeployment()
	return d.GetDeployedRevision()
}

func (c *applianceWrapper) DeploymentType() time.Time {
	d := c.a.GetIdApplianceDeployment()
	return d.GetDeploymentTime()
}

func (c *applianceWrapper) IsDeployed() bool {
	return c.a.GetIdApplianceDeployment().DeploymentTime != nil
}

func (c *applianceWrapper) Providers() []string {
	p := c.c.GetProviders()
	sort.Strings(p)
	return p
}

func (c *applianceWrapper) ProvidersCount() int {
	return len(c.c.GetProviders())
}

func (c *applianceWrapper) IdSources() []string {
	p := c.c.GetIdSources()
	sort.Strings(p)
	return p
}

func (c *applianceWrapper) IdSourcesCount() int {
	return len(c.c.GetIdSources())
}

func (c *applianceWrapper) ExecEnvsCount() int {
	return len(c.c.GetExecEnvs())
}

func (c *applianceWrapper) ExecEnvs() []string {
	p := c.c.GetExecEnvs()
	sort.Strings(p)
	return p
}

func (c *applianceWrapper) HasBundles() bool {
	return len(c.a.IdApplianceDefinition.GetRequiredBundles()) > 0
}

func (c *applianceWrapper) Bundles() string {
	return strings.Join(c.a.IdApplianceDefinition.GetRequiredBundles(), ", ")
}

func (c *applianceWrapper) Branding() string {
	return *c.a.IdApplianceDefinition.UserDashboardBranding.Name
}
