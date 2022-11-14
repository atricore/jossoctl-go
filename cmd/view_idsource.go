/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"
	"os"

	"github.com/atricore/josso-cli-go/formatter"
	"github.com/spf13/cobra"

	api "github.com/atricore/josso-api-go"
)

var IdSourcesFormatters = []formatter.IdSourceFormatter{
	{
		IdSourceType:   "DbIdentitySourceDTO",
		IdSourceFormat: formatter.NewDbIdSouceFormat,
		IdSourceWriter: func(ctx formatter.IdSourceContext, containers []api.IdSourceContainerDTO) error {
			var idsource []api.DbIdentitySourceDTO
			for _, c := range containers {
				if c.GetType() == "DbIdentitySourceDTO" {
					db, err := client.Client().GetDbIdentitySourceDTO(id_or_name, c.GetName())
					if err != nil {
						return err
					}
					idsource = append(idsource, db)
				}
			}

			formatter.IdSourceDBWrite(ctx, idsource)
			return nil
		},
	},
}

var DefaultIdSourcesFormatters = formatter.IdSourceFormatter{
	IdSourceType:   "__default__",
	IdSourceFormat: formatter.NewIdSourceContainerFormat,
	IdSourceWriter: func(ctx formatter.IdSourceContext, containers []api.IdSourceContainerDTO) error {
		var idsources []api.IdentitySourceDTO

		for _, c := range containers {
			idsources = append(idsources, *c.IdSource)
		}
		formatter.IdSourceWrite(ctx, idsources)

		return nil
	},
}

// appliancesCmd represents the appliances command
var viewIdSourcesCmd = &cobra.Command{
	Use:   "idsource",
	Short: "view id Source",
	Long:  `view federated id source`,
	Run:   viewIdSources,
	Args:  cobra.ExactArgs(1),
}

func viewIdSources(cmd *cobra.Command, args []string) {
	p, err := client.Client().GetIdSource(id_or_name, args[0])
	if err != nil {
		client.Error(err)
		os.Exit(1)
	}

	if p.Name == nil {
		client.Error(fmt.Errorf("idsource %s not found in appliance %s", args[0], id_or_name))
		os.Exit(1)
	}

	source := func() string {
		if print_raw {
			return "raw"
		}
		return "pretty"
	}

	f := getISourcesFormatter(p.GetType())

	ctx := formatter.IdSourceContext{
		Context: formatter.Context{
			Output: client.Out(),
			Format: f.IdSourceFormat(source(), quiet),
		},
	}

	lsa := []api.IdSourceContainerDTO{p}
	err = f.IdSourceWriter(ctx, lsa)
	if err != nil {
		client.Error(err)
		os.Exit(1)
	}
}

func init() {
	viewCmd.AddCommand(viewIdSourcesCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// appliancesCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// appliancesCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func getISourcesFormatter(pType string) formatter.IdSourceFormatter {

	for _, f := range IdSourcesFormatters {
		if f.IdSourceType == pType {
			return f
		}
	}

	return DefaultIdSourcesFormatters
}
