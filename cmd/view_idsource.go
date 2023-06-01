/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"github.com/atricore/josso-cli-go/render"
	"github.com/spf13/cobra"
)

// appliancesCmd represents the appliances command
var viewIdSourcesCmd = &cobra.Command{
	Use:   "idsource",
	Short: "view id Source",
	Long:  `view federated id source`,
	Run:   viewIdSources,
	Args:  cobra.ExactArgs(1),
}

func viewIdSources(cmd *cobra.Command, args []string) {
	render.RenderIDSourceToWriter(Client, id_or_name, args[0], source(), quiet, Client.Out())
}

func init() {
	viewCmd.AddCommand(viewIdSourcesCmd)
}
