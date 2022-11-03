/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	api "github.com/atricore/josso-api-go"
	"github.com/spf13/cobra"
)

// importCmd represents the importAppliance command
var importApplianceCmd = &cobra.Command{
	Use:     "appliance",
	Aliases: []string{"a"},
	Short:   "import Appliance ",
	Long:    `Import Identity Appliance definition.`,
	Run:     importApplianceCobra,
	Args:    cobra.MaximumNArgs(1),
}

func importApplianceCobra(cmd *cobra.Command, args []string) {
	if len(args) > 0 {
		importAppliance(args[0])
	} else {
		importAppliance(id_or_name)

	}
}

func importAppliance(a string) api.IdentityApplianceDefinitionDTO {
	appliance, err := client.Client().ImportAppliance(a)
	if err != nil {
		printError(err)
	}
	return appliance
}

func init() {
	importCmd.AddCommand(importApplianceCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// importApplianceCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// importApplianceCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	//importApplianceCmd.Flags().StringP("appliance", "n", false, "Help message for toggle")
}
