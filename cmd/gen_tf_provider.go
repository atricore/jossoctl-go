package cmd

import (
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

func genTFProvider(idaName string, pName string, oType string, oPrefix string, oFile string, replace bool) error {
	return genTFForResource(idaName, "provider", pName, oType, oPrefix, oFile, replace,
		render.RenderProviderToFile, render.RenderProviderToWriter)

}

func init() {
	genTFCmd.AddCommand(genTFProviderCmd)
	genTFProviderCmd.PersistentFlags().StringVarP(&fName, "file", "f", "", "Store the output in the given file name")
}
