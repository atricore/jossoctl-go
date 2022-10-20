/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/spf13/cobra"
)

// ImportProviderCmd represents the ImportProvider command
var importDefinitionCmd = &cobra.Command{
	Use:     "import definition",
	Aliases: []string{"d"},
	Short:   "import definition",
	Long:    `Import definition`,
	//Run:	     ,
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
}
