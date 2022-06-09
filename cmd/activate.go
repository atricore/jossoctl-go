/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// listCmd represents the list command
var activateCmd = &cobra.Command{
	Use:   "activate",
	Short: "Activate all agent resources",
	Args:  cobra.MaximumNArgs(0),
	Long: `Activate all agent resources, for example:
	
	You can activate tomcat, weblogic, etc`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("activate called")
	},
}

func init() {
	rootCmd.AddCommand(activateCmd)
}
