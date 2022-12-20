/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"os"

	"github.com/atricore/josso-cli-go/formatter"
	"github.com/spf13/cobra"
)

// appliancesCmd represents the appliances command
var listIdSourcesCmd = &cobra.Command{
	Use:     "idsources",
	Aliases: []string{"i"},
	Short:   "list idsources",
	Long:    `list identity sources in an appliance`,
	Run:     listIdSourcesCobra,
	Args:    cobra.ExactArgs(0),
}

func listIdSourcesCobra(cmd *cobra.Command, args []string) {
	listIdSources()
}

func listIdSources() {
	a, err := client.Client().GetIdSources(id_or_name)
	if err != nil {
		client.Error(err)
		os.Exit(1)
	}

	source := func() string {
		if print_raw {
			return "raw"
		}
		return "table"
	}

	ctx := formatter.IdSourceContext{
		Context: formatter.Context{
			Output: client.Out(),
			Format: formatter.NewIdSourceContainerFormat(source(), quiet),
		},
	}
	err = formatter.IdSourceContainerWrite(ctx, a)
	if err != nil {
		client.Error(err)
		os.Exit(1)
	}
}

func init() {
	listCmd.AddCommand(listIdSourcesCmd)
}
