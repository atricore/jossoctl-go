/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/atricore/josso-cli-go/util"
	"github.com/spf13/cobra"
)

// ExportApplianceCmd represents the ExportAppliance command
var exportApplianceCmd = &cobra.Command{
	Use:     "appliance",
	Aliases: []string{"a"},
	Short:   "export appliance definition",
	Long:    `exports an identity appliance to a file. Supported formats are json and binary.`,
	Args:    cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {

		// format
		format := "binary"
		format = cmd.Flag("format").Value.String()

		// output
		out := cmd.Flag("output").Value.String()

		// replace
		replace := cmd.Flag("replace").Value.String() == "true"

		// export appliance
		err := exportAppliance(id_or_name, format, out, replace)
		if err != nil {
			printError(err)
			os.Exit(1)
		}

		return nil
	},
}

func init() {
	exportCmd.AddCommand(exportApplianceCmd)

	exportApplianceCmd.Flags().StringP("format", "f", "binary", "appliance format: json, binary")
	exportApplianceCmd.Flags().BoolP("replace", "r", false, "replace the file if it exists")
	exportApplianceCmd.Flags().StringP("output", "o", "", "appliance destination file")
}

func exportAppliance(id_or_name string, format string, out string, replace bool) error {
	if format == "" {
		return fmt.Errorf("format is required")
	}

	if out == "" {
		return fmt.Errorf("output file is required")
	}

	content, err := Client.Client().ExportAppliance(id_or_name, format)
	if err != nil {
		return err
	}

	// base 64 decode content to bin
	bin, err := base64.StdEncoding.DecodeString(content)

	err = util.WriteBytesToFile(out, bin, replace)
	if err != nil {
		return err
	}

	return nil
}
