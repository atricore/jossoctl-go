/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// exportagentCmd represents the exportagent command
var exportAgentCfgCmd = &cobra.Command{
	Use:   "agent-cfg",
	Short: "Export agent configuartion file",
	Long:  `Export JOSSO agent configurtion file for a given execution environment.`,

	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO")
	},
}

func init() {
	exportCmd.AddCommand(exportAgentCfgCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	exportAgentCfgCmd.Flags().BoolP("replace", "r", false, "Replace out file")
	exportAgentCfgCmd.Flags().StringP("output", "o", "", "Agent configuration destination file")
}
