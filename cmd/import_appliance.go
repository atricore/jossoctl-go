/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"errors"
	"os"

	api "github.com/atricore/josso-api-go"
	"github.com/spf13/cobra"
)

// importCmd represents the importAppliance command
var importApplianceCmd = &cobra.Command{
	Use:     "appliance",
	Aliases: []string{"a"},
	Short:   "import Appliance ",
	Long:    `Import Identity Appliance definition.`,
	RunE:    importApplianceCobra,
	Args:    cobra.MaximumNArgs(1),
}

func importApplianceCobra(cmd *cobra.Command, args []string) error {
	var a api.IdentityApplianceDefinitionDTO
	var err error

	// format
	format := "binary"
	format = cmd.Flag("format").Value.String()

	// file
	file := cmd.Flag("input").Value.String()
	if file == "" {
		return errors.New("missing input file")
	}

	// import appliance
	a, err = importAppliance(file, format)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	printOut("appliance imported: " + a.GetName())
	return nil
}

func importAppliance(file string, format string) (api.IdentityApplianceDefinitionDTO, error) {

	var a api.IdentityApplianceDefinitionDTO
	var err error

	if format != "json" && format != "binary" {
		return a, errors.New("invalid format, must be json or binary")
	}

	// read file into content as string
	content, err := os.ReadFile(file)
	if err != nil {
		return a, err
	}
	return client.Client().ImportAppliance(content, format)

}

func init() {
	importCmd.AddCommand(importApplianceCmd)
	importApplianceCmd.Flags().StringP("format", "f", "binary", "appliance format: json, binary")
	importApplianceCmd.Flags().StringP("input", "i", "", "input resource")
}
