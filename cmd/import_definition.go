/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// ImportProviderCmd represents the ImportProvider command
var importDefinitionCmd = &cobra.Command{
	Use:     "definition",
	Aliases: []string{"def"},
	Short:   "import definition",
	Long: `Import definition
	
SYNTAX
	appliance:import-definition [options]	`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO!")
	},
	Args: cobra.ExactArgs(1),
}

func init() {
	importCmd.AddCommand(importDefinitionCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	importDefinitionCmd.Flags().StringP("modify", "m", "", "Enable Identity Appliance modification")
	importDefinitionCmd.Flags().StringP("description", "", "", "New Identity Appliance description")
	importDefinitionCmd.Flags().StringP("location", "l", "", "New Identity Appliance location")
	importDefinitionCmd.Flags().StringP("input", "i", "", "Identity Appliance export file")
	importDefinitionCmd.Flags().StringP("name", "n", "", "New Identity Appliance name")
	importDefinitionCmd.Flags().StringP("realm", "r", "", "New Identity Appliance realm")

}
