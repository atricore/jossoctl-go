package cmd

import (
	"fmt"

	"github.com/atricore/josso-cli-go/render"
	"github.com/spf13/cobra"
)

var genTFProviderCmd = &cobra.Command{
	Use:     "provider",
	Aliases: []string{"p"},
	Short:   "generate terraform resource descriptor for provider",
	Long:    `generate terraform resource descriptor for federated provider`,
	Run:     genTFProviderRun,
	Args:    cobra.ExactArgs(1),
}

func genTFProviderRun(cmd *cobra.Command, args []string) {
	if outputType == "file" {

		outputFilename := fName
		// if fName has a value use it, otherwise use the default : "iamtf_appliance_+id_or_name+.tf"
		if outputFilename == "" {
			outputFilename = "iamtf-provider-" + id_or_name + ".tf"
		}
		err := render.RenderProviderToFile(Client, id_or_name, args[0], "tf", quiet, outputFilename, replace)
		if err != nil {
			Client.Error(err)
			return
		}
	} else if outputType == "stdout" {
		render.RenderProviderToWriter(Client, id_or_name, args[0], "tf", quiet, Client.Out())
	} else {
		Client.Error(fmt.Errorf("invalid output type: %s", outputType))
	}
}
