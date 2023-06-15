package cmd

import (
	"fmt"
	"os"

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
	err := genTFProvider(id_or_name, args[0], outputType, fName, replace)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}

}

func genTFProvider(id_or_name string, pName string, oType string, oFile string, replace bool) error {
	if oType == "file" {
		// if fName has a value use it, otherwise use the default : "iamtf_appliance_+id_or_name+.tf"
		if oFile == "" {
			oFile = id_or_name + "-provider-" + pName + ".tf"
		}
		return render.RenderProviderToFile(Client, id_or_name, pName, "tf", quiet, oFile, replace)
	} else if outputType == "stdout" {
		return render.RenderProviderToWriter(Client, id_or_name, pName, "tf", quiet, Client.Out())

	}

	return fmt.Errorf("invalid output type: %s", outputType)

}

func init() {
	genTFCmd.AddCommand(genTFProviderCmd)
	genTFProviderCmd.PersistentFlags().StringVarP(&fName, "file", "f", "", "Store the output in the given file name")
}
