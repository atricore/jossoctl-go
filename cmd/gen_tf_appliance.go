package cmd

import (
	"fmt"
	"os"

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
	Run:     genTFApplianceRun,
}

func genTFApplianceRun(cmd *cobra.Command, args []string) {
	err := genTFAppliance(id_or_name, outputType, fName, replace)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}
}

func genTFAppliance(id_or_name string, oType string, oFile string, replace bool) error {

	// Check output type var
	if oType == "file" {
		if oFile == "" {
			oFile = id_or_name + "-appliance-" + id_or_name + ".tf"
		}
		return render.RenderApplianceToFile(Client, id_or_name, "tf", quiet, oFile, replace)
	} else if oType == "stdout" {
		return render.RenderApplianceToWriter(Client, id_or_name, "tf", quiet, Client.Out())
	} else {
		return fmt.Errorf("invalid output type: %s", oType)
	}
}

func init() {
	genTFCmd.AddCommand(genTFApplianceCmd)
	genTFApplianceCmd.PersistentFlags().StringVarP(&fName, "file", "f", "", "Store the output in the given file name")
}
