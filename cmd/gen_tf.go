package cmd

import (
	"fmt"
	"io"
	"os"

	cli "github.com/atricore/josso-cli-go/cli"
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
var prefix string

func genTF(cmd *cobra.Command, args []string) {

	idaName, err := getIdaName(id_or_name)
	err = GenTF(idaName)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}
}

func genTFRun(cmd *cobra.Command, args []string, generateFn func(idaName string, pName string, oType string, oPrefix string, oFile string, replace bool) error) {
	idaName, err := getIdaName(id_or_name)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}

	rName := ""
	if len(args) > 0 {
		rName = args[0]
	}
	err = generateFn(idaName, rName, outputType, prefix, fName, replace)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}

}

func GenTF(idaName string) error {

	err := genTFAppliance(idaName, idaName, outputType, prefix, "", replace)
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
		genTFProvider(idaName, *p.Name, outputType, prefix, "", replace)
	}

	for _, i := range is {
		genTFIDSource(idaName, *i.Name, outputType, prefix, "", replace)
	}

	for _, e := range ex {

		if e.GetCaptive() {
			continue
		}

		genTFExecEnv(idaName, *e.Name, outputType, prefix, "", replace)
	}

	return nil
}

/**
 * Generate terraform resource file for an appliance
 */
func genTFForResource(idaName string, rType string, iName string, oType string, oPrefix string, oFile string, replace bool,
	fileRenderFunc func(cli.Cli, string, string, string, bool, string, bool) error,
	stdoutRenderFunc func(cli.Cli, string, string, string, bool, io.Writer) error) error {
	switch oType {
	case "file":
		if oFile == "" {
			oFile = getTFFileName(oPrefix, idaName, rType, iName)
		}
		msg := fmt.Sprintf("Generating terraform resource file %s\n", oFile)

		Client.Out().Write([]byte(msg))

		return fileRenderFunc(Client, idaName, iName, "tf", quiet, oFile, replace)
	case "stdout":
		return stdoutRenderFunc(Client, idaName, iName, "tf", quiet, Client.Out())
	default:
		return fmt.Errorf("invalid output type: %s", oType)
	}
}

func init() {
	rootCmd.AddCommand(genTFCmd)
	genTFCmd.PersistentFlags().BoolVarP(&replace, "replace", "r", false, "Replace output file if it exists")
	genTFCmd.PersistentFlags().StringVarP(&outputType, "output", "o", "stdout", "Output type (file or stdout)")
	genTFCmd.PersistentFlags().StringVarP(&prefix, "prefix", "p", "", "Resource file prefix, default is the appliance name")

}

func getIdaName(id_or_name string) (string, error) {
	// Resolve to ida name in case we have an ID
	a, err := Client.Client().GetApplianceContainer(id_or_name)
	if err != nil {
		return "", err
	}
	return *a.Appliance.Name, nil
}

func getTFFileName(oPrefix string, idaName string, rType string, rName string) string {
	prefix := idaName
	if oPrefix != "" {
		prefix = oPrefix
	}
	return prefix + "-" + rType + "-" + rName + ".tf"
}
