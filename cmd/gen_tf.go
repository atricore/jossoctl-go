package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// Import represents the Import command
var genTFCmd = &cobra.Command{
	Use:     "generate-tf",
	Aliases: []string{"tf"},
	Short:   "generate terraform resource file",
	Args:    cobra.ExactArgs(0),
	Long:    `Generate empty terraform resource file so you can use terraform import later.`,
	Run:     genTF,
}

var fName, outputType string
var replace bool

func genTF(cmd *cobra.Command, args []string) {
	err := GenTF(id_or_name)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}
}

func GenTF(id_or_name string) error {

	err := genTFAppliance(id_or_name, outputType, "", replace)
	if err != nil {
		return err
	}

	// If appliance was generated, then generate providers

	ps, err := Client.Client().GetProviders(id_or_name)
	if err != nil {
		return err
	}

	is, err := Client.Client().GetIdSources(id_or_name)
	if err != nil {
		return err
	}

	ex, err := Client.Client().GetExecEnvs(id_or_name)
	if err != nil {
		return err
	}

	for _, p := range ps {
		genTFProvider(id_or_name, *p.Name, outputType, "", replace)
	}

	for _, i := range is {
		genTFIDSource(id_or_name, *i.Name, outputType, "", replace)
	}

	for _, e := range ex {
		genTFExecEnv(id_or_name, *e.Name, outputType, "", replace)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(genTFCmd)
	genTFCmd.PersistentFlags().BoolVarP(&replace, "replace", "r", false, "Replace output file if it exists")
	genTFCmd.PersistentFlags().StringVarP(&outputType, "output", "o", "stdout", "Output type (file or stdout)")

}
