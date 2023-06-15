package cmd

import (
	"fmt"

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

func genTFAppliance(idaName string, iName string, oType string, oFile string, replace bool) error {

	// Check output type var
	if oType == "file" {
		if oFile == "" {
			oFile = idaName + "-appliance-" + idaName + ".tf"
		}
		return render.RenderApplianceToFile(Client, idaName, "tf", quiet, oFile, replace)
	} else if oType == "stdout" {
		return render.RenderApplianceToWriter(Client, idaName, "tf", quiet, Client.Out())
	} else {
		return fmt.Errorf("invalid output type: %s", oType)
	}
}

func init() {
	genTFCmd.AddCommand(genTFApplianceCmd)
	genTFApplianceCmd.PersistentFlags().StringVarP(&fName, "file", "f", "", "Store the output in the given file name")
}
