/*
Copyright © 2022 atricore <sgonzalez@atricore.com>
*/
package cmd

import (
	"github.com/atricore/josso-cli-go/render"
	"github.com/spf13/cobra"
)

// brandingsCmd represents the brandings command
var viewBrandingCmd = &cobra.Command{
	Use:     "branding",
	Aliases: []string{"b"},
	Short:   "view branding",
	Long:    `view identity branding`,
	Run:     viewBranding,
	Args:    cobra.ExactArgs(1),
}

func viewBranding(cmd *cobra.Command, args []string) {
	err := render.RenderBrandingToWriter(Client, args[0], args[0], source(), quiet, Client.Out())
	if err != nil {
		Client.Error(err)
	}
}

func init() {
	viewCmd.AddCommand(viewBrandingCmd)
}
