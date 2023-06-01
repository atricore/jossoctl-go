/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// ValidateCmd represents the Validate command
var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "validate identity appliance",
	Long:  `Validate identity appliance.`,
	Run: func(cmd *cobra.Command, args []string) {
		validateApplianceCobra(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)
}

func validateApplianceCobra(cmd *cobra.Command, args []string) {
	ValidateAppliance(id_or_name)
}

func ValidateAppliance(a string) {
	err, validations := Client.Client().ValidateAppliance(a)
	if err != nil {
		fmt.Printf("appliance %s is NOT valid\n", id_or_name)
		printError(err)
		// iterate validations and print as errors using printError

		printOut("\nvalidations:")
		for _, v := range validations {
			printError(fmt.Errorf(v))
		}
		os.Exit(1)
	}
	fmt.Printf("appliance %s is valid\n", id_or_name)
}
