/*
Copyright © 2022 atricore <sgonzalez@atricore.com>
*/
package cmd

import (
	"os"

	"github.com/atricore/josso-cli-go/render"
	"github.com/spf13/cobra"
)

// appliancesCmd represents the appliances command
var viewIdSourcesCmd = &cobra.Command{
	Use:   "idsource",
	Short: "view identity source",
	Long:  `view SSO identity source`,
	Run:   viewIdSources,
	Args:  cobra.ExactArgs(1),
}

func viewIdSources(cmd *cobra.Command, args []string) {
	err := render.RenderIDSourceToWriter(Client, id_or_name, args[0], source(), quiet, Client.Out())
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}
}

func init() {
	viewCmd.AddCommand(viewIdSourcesCmd)
}
