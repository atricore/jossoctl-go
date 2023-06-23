package cmd

import (
	"github.com/atricore/josso-cli-go/render"

	"github.com/spf13/cobra"
)

// appliancesCmd represents the appliances command
var genTFApplianceCmd = &cobra.Command{
	Use:     "appliance",
	Aliases: []string{"a"},
	Short:   "view appliance",
	Long:    `generate identity appliance terraform resource file`,
	Args:    cobra.ExactArgs(0),
	Run:     func(cmd *cobra.Command, args []string) { genTFRun(cmd, args, genTFAppliance) },
}

func genTFAppliance(idaName string, iName string, oType string, oPrefix string, oFile string, replace bool) error {
	return genTFForResource(idaName, "appliance", iName, oType, oPrefix, oFile, replace,
		render.RenderApplianceToFile, render.RenderApplianceToWriter)
}

func init() {
	genTFCmd.AddCommand(genTFApplianceCmd)
	genTFApplianceCmd.PersistentFlags().StringVarP(&fName, "file", "f", "", "Store the output in the given file name")
}
