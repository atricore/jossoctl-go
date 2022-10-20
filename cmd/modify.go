/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/spf13/cobra"
)

// modifycmd represents the modify command
var modifyCmd = &cobra.Command{
	Use:   "modify",
	Short: "modify identity appliance",
	Long:  `Modify identity appliance.`,

	Args: cobra.MaximumNArgs(1),
}

func init() {
	rootCmd.AddCommand(modifyCmd)
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
