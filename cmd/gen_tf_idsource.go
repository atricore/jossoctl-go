package cmd

import (
	"fmt"

	"github.com/atricore/josso-cli-go/render"
	"github.com/spf13/cobra"
)

var genTFIDSourceCmd = &cobra.Command{
	Use:     "idsource",
	Aliases: []string{"i"},
	Short:   "generate terraform resource descriptor for identity source",
	Long:    `generate terraform resource descriptor for identity source`,
	Run:     func(cmd *cobra.Command, args []string) { genTFRun(cmd, args, genTFIDSource) },
	Args:    cobra.ExactArgs(1),
}

func genTFIDSource(idaName string, iName string, oType string, oFile string, replace bool) error {

	if oType == "file" {
		// if fName has a value use it, otherwise use the default : "iamtf_appliance_+idaName+.tf"
		if oFile == "" {
			oFile = idaName + "-idsource-" + idaName + "-" + iName + ".tf"
		}
		return render.RenderIDSourceToFile(Client, idaName, iName, "tf", quiet, oFile, replace)
	} else if outputType == "stdout" {
		return render.RenderIDSourceToWriter(Client, idaName, iName, "tf", quiet, Client.Out())
	}

	return fmt.Errorf("invalid output type: %s", outputType)

}

func init() {
	genTFCmd.AddCommand(genTFIDSourceCmd)
	genTFIDSourceCmd.PersistentFlags().StringVarP(&fName, "file", "f", "", "Store the output in the given file name")
}
