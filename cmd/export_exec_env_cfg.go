/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"
	"os"

	// import util.go

	"github.com/atricore/josso-cli-go/util"
	"github.com/spf13/cobra"
)

// exportagentCmd represents the exportagent command
var exportExecEnvCfgCmd = &cobra.Command{
	Use:     "exec-env-cfg name",
	Aliases: []string{"ee-cfg"},
	Short:   "Export execution environment configuartion file (JOSSO agent configuration)",
	Long:    `Export JOSSO agent configurtion file for a given execution environment.`,

	Args: cobra.ExactArgs(1),
	Run:  exportExecEnvCfgCobra,
}

func init() {
	exportCmd.AddCommand(exportExecEnvCfgCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	exportExecEnvCfgCmd.Flags().BoolP("replace", "r", false, "Replace out file")
	exportExecEnvCfgCmd.Flags().StringP("output", "o", "", "Agent configuration destination file")
	exportExecEnvCfgCmd.Flags().BoolP("console", "c", false, "Agent configuration exported to console (stdout)")
}

func exportExecEnvCfgCobra(cmd *cobra.Command, args []string) {

	// value of r flag
	replace, _ := cmd.Flags().GetBool("replace")
	// value of o flag
	output, _ := cmd.Flags().GetString("output")

	console, _ := cmd.Flags().GetBool("console")

	ExportExecEnvCfg(id_or_name, args[0], output, console, replace)
}

func ExportExecEnvCfg(id_or_name string, ee string, out string, console bool, replace bool) {
	cfg, fileName, err := client.Client().ExportExecEnvCfg(id_or_name, ee)
	if err != nil {
		client.Error(err)
		os.Exit(1)
	}

	if out == "" {
		out = fileName
	}

	// write cfg to out file, only overwise if replace is true

	if console {
		fmt.Println(cfg)
	} else {
		err = util.WriteToFile(out, cfg, replace)
		if err != nil {
			client.Error(err)
			os.Exit(1)
		}
		fmt.Printf("Exec env configuration file exported to %s\n", fileName)
	}

}
