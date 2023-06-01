/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"github.com/atricore/josso-cli-go/render"
	"github.com/spf13/cobra"
)

// appliancesCmd represents the appliances command
var viewProviderCmd = &cobra.Command{
	Use:     "provider",
	Aliases: []string{"p"},
	Short:   "view provider",
	Long:    `view federated provider`,
	Run:     viewProvider,
	Args:    cobra.ExactArgs(1),
}

func viewProvider(cmd *cobra.Command, args []string) {
	render.RenderProviderToWriter(Client, id_or_name, args[0], source(), quiet, Client.Out())
}

func init() {
	viewCmd.AddCommand(viewProviderCmd)
}
