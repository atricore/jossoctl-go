package cmd

import (
	"fmt"
	"os"

	"github.com/atricore/josso-cli-go/render"
	"github.com/spf13/cobra"
)

var genTFExecEnvCmd = &cobra.Command{
	Use:     "execenv",
	Aliases: []string{"e"},
	Short:   "generate terraform resource descriptor for execution environment",
	Long:    `generate terraform resource descriptor for execution environment`,
	Run:     genTFExecEnvRun,
	Args:    cobra.ExactArgs(1),
}

func genTFExecEnvRun(cmd *cobra.Command, args []string) {
	err := genTFExecEnv(id_or_name, args[0], outputType, fName, replace)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}

}

func genTFExecEnv(id_or_name string, iName string, oType string, oFile string, replace bool) error {

	if oType == "file" {
		// if fName has a value use it, otherwise use the default : "iamtf_appliance_+id_or_name+.tf"
		if oFile == "" {
			oFile = "iamtf-execenv-" + id_or_name + "-" + iName + ".tf"
		}
		return render.RenderExecEnvToFile(Client, id_or_name, iName, "tf", quiet, oFile, replace)
	} else if outputType == "stdout" {
		return render.RenderExecEnvToWriter(Client, id_or_name, iName, "tf", quiet, Client.Out())
	}

	return fmt.Errorf("invalid output type: %s", outputType)

}

func init() {
	genTFCmd.AddCommand(genTFExecEnvCmd)
	genTFExecEnvCmd.PersistentFlags().StringVarP(&fName, "file", "f", "", "Store the output in the given file name")
}
