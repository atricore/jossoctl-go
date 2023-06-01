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
	Run:     genTFIDSourceRun,
	Args:    cobra.ExactArgs(1),
}

func genTFIDSourceRun(cmd *cobra.Command, args []string) {
	if outputType == "file" {

		outputFilename := fName
		// if fName has a value use it, otherwise use the default : "iamtf_appliance_+id_or_name+.tf"
		if outputFilename == "" {
			outputFilename = "iamtf-idsource-" + id_or_name + ".tf"
		}
		err := render.RenderIDSourceToFile(Client, id_or_name, args[0], "tf", quiet, outputFilename, replace)
		if err != nil {
			Client.Error(err)
			return
		}
	} else if outputType == "stdout" {
		render.RenderIDSourceToWriter(Client, id_or_name, args[0], "tf", quiet, Client.Out())
	} else {
		Client.Error(fmt.Errorf("invalid output type: %s", outputType))
	}
}
