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

	idaName, err := getIdaName(id_or_name)
	err = GenTF(idaName)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}
}

func genTFRun(cmd *cobra.Command, args []string, generateFn func(idaName string, pName string, oType string, oFile string, replace bool) error) {
	idaName, err := getIdaName(id_or_name)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}
	err = generateFn(idaName, args[0], outputType, fName, replace)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}

}

func GenTF(idaName string) error {

	err := genTFAppliance(idaName, idaName, outputType, "", replace)
	if err != nil {
		return err
	}

	// If appliance was generated, then generate providers

	ps, err := Client.Client().GetProviders(idaName)
	if err != nil {
		return err
	}

	is, err := Client.Client().GetIdSources(idaName)
	if err != nil {
		return err
	}

	ex, err := Client.Client().GetExecEnvs(idaName)
	if err != nil {
		return err
	}

	for _, p := range ps {
		genTFProvider(idaName, *p.Name, outputType, "", replace)
	}

	for _, i := range is {
		genTFIDSource(idaName, *i.Name, outputType, "", replace)
	}

	for _, e := range ex {
		genTFExecEnv(idaName, *e.Name, outputType, "", replace)
	}

	return nil
}

func init() {
	rootCmd.AddCommand(genTFCmd)
	genTFCmd.PersistentFlags().BoolVarP(&replace, "replace", "r", false, "Replace output file if it exists")
	genTFCmd.PersistentFlags().StringVarP(&outputType, "output", "o", "stdout", "Output type (file or stdout)")

}

func getIdaName(id_or_name string) (string, error) {
	// Resolve to ida name in case we have an ID
	a, err := Client.Client().GetApplianceContainer(id_or_name)
	if err != nil {
		return "", err
	}
	return *a.Appliance.Name, nil
}
