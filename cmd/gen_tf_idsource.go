package cmd

import (
	"fmt"
	"os"

	"github.com/atricore/josso-cli-go/render"
	"github.com/spf13/cobra"
)

var genTFIDSourceCmd = &cobra.Command{
	Use:     "idsource",
	Aliases: []string{"i"},
	Short:   "generate terraform resource descriptor for identity source",
	Long:    `generate terraform resource descriptor for identity source`,
	Run:     genTFIDSourceRun,
	Args:    cobra.ExactArgs(1),
}

func genTFIDSourceRun(cmd *cobra.Command, args []string) {
	err := genTFIDSource(id_or_name, args[0], outputType, fName, replace)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}

}

func genTFIDSource(id_or_name string, iName string, oType string, oFile string, replace bool) error {

	if oType == "file" {
		// if fName has a value use it, otherwise use the default : "iamtf_appliance_+id_or_name+.tf"
		if oFile == "" {
			oFile = id_or_name + "-idsource-" + id_or_name + "-" + iName + ".tf"
		}
		return render.RenderIDSourceToFile(Client, id_or_name, iName, "tf", quiet, oFile, replace)
	} else if outputType == "stdout" {
		return render.RenderIDSourceToWriter(Client, id_or_name, iName, "tf", quiet, Client.Out())
	}

	return fmt.Errorf("invalid output type: %s", outputType)

}

func init() {
	genTFCmd.AddCommand(genTFIDSourceCmd)
	genTFIDSourceCmd.PersistentFlags().StringVarP(&fName, "file", "f", "", "Store the output in the given file name")
}
