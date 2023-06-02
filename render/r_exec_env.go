package render

import (
	"fmt"
	"io"

	api "github.com/atricore/josso-api-go"
	"github.com/atricore/josso-cli-go/cli"
	"github.com/atricore/josso-cli-go/render/formatter"
)

var ExecEnvFormatters = []formatter.ExecEnvFormatter{
	{
		ExecEnvType:   "TomcatExecutionEnvironment",
		ExecEnvFormat: formatter.NewTomcatFormat,
		ExecEnvWriter: func(ctx formatter.ExecEnvContext, id_or_name string, containers []api.ExecEnvContainerDTO) error {
			var execEnv []api.TomcatExecutionEnvironmentDTO
			for _, c := range containers {
				if c.GetType() == "TomcatExecutionEnvironment" {
					db, err := ctx.Client.Client().GetTomcatExeEnv(id_or_name, c.GetName())
					if err != nil {
						return err
					}
					execEnv = append(execEnv, db)
				}
			}

			return formatter.TomcatExecEnvWrite(ctx, execEnv)
		},
	},
	{
		ExecEnvType:   "WindowsIISExecutionEnvironment",
		ExecEnvFormat: formatter.NewWindowsIISFormat,
		ExecEnvWriter: func(ctx formatter.ExecEnvContext, id_or_name string, containers []api.ExecEnvContainerDTO) error {
			var execEnv []api.WindowsIISExecutionEnvironmentDTO
			for _, c := range containers {
				if c.GetType() == "WindowsIISExecutionEnvironment" {
					db, err := ctx.Client.Client().GetIISExeEnv(id_or_name, c.GetName())
					if err != nil {
						return err
					}
					execEnv = append(execEnv, db)
				}
			}

			return formatter.WindowsIISExecEnvWrite(ctx, execEnv)
		},
	},
	{
		ExecEnvType:   "PHPExecutionEnvironment",
		ExecEnvFormat: formatter.NewPHPFormat,
		ExecEnvWriter: func(ctx formatter.ExecEnvContext, id_or_name string, containers []api.ExecEnvContainerDTO) error {
			var execEnv []api.PHPExecutionEnvironmentDTO
			for _, c := range containers {
				if c.GetType() == "PHPExecutionEnvironment" {
					db, err := ctx.Client.Client().GetPhpExeEnv(id_or_name, c.GetName())
					if err != nil {
						return err
					}
					execEnv = append(execEnv, db)
				}
			}

			return formatter.PHPExecEnvWrite(ctx, execEnv)
		},
	},
	{
		ExecEnvType:   "WeblogicExecutionEnvironment",
		ExecEnvFormat: formatter.NewWeblogicFormat,
		ExecEnvWriter: func(ctx formatter.ExecEnvContext, id_or_name string, containers []api.ExecEnvContainerDTO) error {
			var execEnv []api.WeblogicExecutionEnvironmentDTO
			for _, c := range containers {
				if c.GetType() == "WeblogicExecutionEnvironment" {
					db, err := ctx.Client.Client().GetWebLogic(id_or_name, c.GetName())
					if err != nil {
						return err
					}
					execEnv = append(execEnv, db)
				}
			}

			return formatter.WeblogicExecEnvWrite(ctx, execEnv)
		},
	},
}

var DefaultExecEnvsFormatters = formatter.ExecEnvFormatter{
	ExecEnvType:   "__default__",
	ExecEnvFormat: formatter.NewExecEnvContainerFormat,
	ExecEnvWriter: func(ctx formatter.ExecEnvContext, id_or_name string, containers []api.ExecEnvContainerDTO) error {
		var execEnvs []api.ExecutionEnvironmentDTO

		for _, c := range containers {
			execEnvs = append(execEnvs, *c.ExecEnv)
		}
		return formatter.ExecEnvWrite(ctx, execEnvs)
	},
}

func RenderExecEnvToFile(c cli.Cli, id_or_name string, pName string, source string, quiet bool, fName string, replace bool) error {
	var f = func(out io.Writer) {
		RenderExecEnvToWriter(c, id_or_name, pName, source, quiet, out)
	}

	return RenderToFile(f, fName, replace)
}

func RenderExecEnvToWriter(c cli.Cli, id_or_name string, idSrcName string, source string, quiet bool, out io.Writer) error {
	p, err := c.Client().GetExecEnv(id_or_name, idSrcName)
	if err != nil {
		return err
	}

	if p.Name == nil {
		return fmt.Errorf("idsource %s not found in appliance %s", idSrcName, id_or_name)
	}

	f := getExecEnvsFormatter(p.GetType())

	ctx := formatter.ExecEnvContext{
		Client: c,
		Context: formatter.Context{
			Output: out,
			Format: f.ExecEnvFormat(source, quiet),
		},
	}

	lsa := []api.ExecEnvContainerDTO{p}
	return f.ExecEnvWriter(ctx, id_or_name, lsa)
}

func getExecEnvsFormatter(pType string) formatter.ExecEnvFormatter {

	for _, f := range ExecEnvFormatters {
		if f.ExecEnvType == pType {
			return f
		}
	}

	return DefaultExecEnvsFormatters
}
