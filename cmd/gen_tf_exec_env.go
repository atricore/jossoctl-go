package cmd

import (
	"fmt"

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

func genTFExecEnv(idaName string, eName string, oType string, oFile string, replace bool) error {

	if oType == "file" {
		// if fName has a value use it, otherwise use the default : "iamtf_appliance_+idaName+.tf"
		if oFile == "" {
			oFile = idaName + "-execenv-" + eName + ".tf"
		}
		return render.RenderExecEnvToFile(Client, idaName, eName, "tf", quiet, oFile, replace)
	} else if outputType == "stdout" {
		return render.RenderExecEnvToWriter(Client, idaName, eName, "tf", quiet, Client.Out())
	}

	return fmt.Errorf("invalid output type: %s", outputType)

}

func init() {
	genTFCmd.AddCommand(genTFExecEnvCmd)
	genTFExecEnvCmd.PersistentFlags().StringVarP(&fName, "file", "f", "", "Store the output in the given file name")
}
