/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"github.com/atricore/josso-cli-go/render"
	"github.com/spf13/cobra"
)

var source = func() string {
	if print_raw {
		return "raw"
	}
	return "pretty"
}

// appliancesCmd represents the appliances command
var viewApplianceCmd = &cobra.Command{
	Use:     "appliance",
	Aliases: []string{"a"},
	Short:   "view appliance",
	Long:    `view identity appliance`,
	Run:     viewAppliance,
}

func viewAppliance(cmd *cobra.Command, args []string) {
	render.RenderApplianceToWriter(Client, id_or_name, source(), quiet, Client.Out())
}

func init() {
	viewCmd.AddCommand(viewApplianceCmd)
}
