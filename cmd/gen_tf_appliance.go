package cmd

import (
	"fmt"

	"github.com/atricore/josso-cli-go/render"

	"github.com/spf13/cobra"
)

// appliancesCmd represents the appliances command
var genTfApplianceCmd = &cobra.Command{
	Use:     "appliance",
	Aliases: []string{"a"},
	Short:   "view appliance",
	Long:    `generate identity appliance terraform resource file`,
	Args:    cobra.ExactArgs(0),
	Run:     genTFApplianceRun,
}

func genTFApplianceRun(cmd *cobra.Command, args []string) {

	// Check output type var
	if outputType == "file" {

		outputFilename := fName
		// if fName has a value use it, otherwise use the default : "iamtf_appliance_+id_or_name+.tf"
		if outputFilename == "" {
			outputFilename = "iamtf-appliance-" + id_or_name + ".tf"
		}
		err := render.RenderApplianceToFile(Client, id_or_name, "tf", quiet, outputFilename, replace)
		if err != nil {
			Client.Error(err)
			return
		}
	} else if outputType == "stdout" {
		render.RenderApplianceToWriter(Client, id_or_name, "tf", quiet, Client.Out())
	} else {
		Client.Error(fmt.Errorf("invalid output type: %s", outputType))
	}
}

func init() {
	genTFCmd.AddCommand(genTfApplianceCmd)
}
