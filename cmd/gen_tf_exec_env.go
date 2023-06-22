package cmd

import (
	"github.com/atricore/josso-cli-go/render"
	"github.com/spf13/cobra"
)

var genTFExecEnvCmd = &cobra.Command{
	Use:     "execenv",
	Aliases: []string{"e"},
	Short:   "generate terraform resource descriptor for execution environment",
	Long:    `generate terraform resource descriptor for execution environment`,
	Run:     func(cmd *cobra.Command, args []string) { genTFRun(cmd, args, genTFExecEnv) },
	Args:    cobra.ExactArgs(1),
}

func genTFExecEnv(idaName string, eName string, oType string, oPrefix string, oFile string, replace bool) error {
	return genTFForResource(idaName, eName, oType, oPrefix, oFile, replace,
		render.RenderExecEnvToFile, render.RenderExecEnvToWriter)

}

func init() {
	genTFCmd.AddCommand(genTFExecEnvCmd)
	genTFExecEnvCmd.PersistentFlags().StringVarP(&fName, "file", "f", "", "Store the output in the given file name")
}
