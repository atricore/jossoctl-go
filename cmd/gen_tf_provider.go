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
	Run:     func(cmd *cobra.Command, args []string) { genTFRun(cmd, args, genTFProvider) },
	Args:    cobra.ExactArgs(1),
}

func genTFProvider(idaName string, pName string, oType string, oFile string, replace bool) error {
	if oType == "file" {
		// if fName has a value use it, otherwise use the default : "iamtf_appliance_+idaName+.tf"
		if oFile == "" {
			oFile = idaName + "-provider-" + pName + ".tf"
		}
		return render.RenderProviderToFile(Client, idaName, pName, "tf", quiet, oFile, replace)
	} else if outputType == "stdout" {
		return render.RenderProviderToWriter(Client, idaName, pName, "tf", quiet, Client.Out())

	}

	return fmt.Errorf("invalid output type: %s", outputType)

}

func init() {
	genTFCmd.AddCommand(genTFProviderCmd)
	genTFProviderCmd.PersistentFlags().StringVarP(&fName, "file", "f", "", "Store the output in the given file name")
}
