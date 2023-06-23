package cmd

import (
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

func genTFIDSource(idaName string, iName string, oType string, oPrefix string, oFile string, replace bool) error {
	return genTFForResource(idaName, "idsource", iName, oType, oPrefix, oFile, replace,
		render.RenderIDSourceToFile, render.RenderIDSourceToWriter)
}

func init() {
	genTFCmd.AddCommand(genTFIDSourceCmd)
	genTFIDSourceCmd.PersistentFlags().StringVarP(&fName, "file", "f", "", "Store the output in the given file name")
}
