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
var viewExecEnvsCmd = &cobra.Command{
	Use:     "execenv",
	Aliases: []string{"e"},
	Short:   "view execution environment",
	Long:    `view SSO execution environment`,
	Run:     viewExecEnvs,
	Args:    cobra.ExactArgs(1),
}

func viewExecEnvs(cmd *cobra.Command, args []string) {
	err := render.RenderExecEnvToWriter(Client, id_or_name, args[0], source(), quiet, Client.Out())
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}
}

func init() {
	viewCmd.AddCommand(viewExecEnvsCmd)
}
