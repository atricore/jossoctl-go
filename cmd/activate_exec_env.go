/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// appliancesCmd represents the appliances command
var activateAgentCmd = &cobra.Command{
	Use:     "exec-env",
	Aliases: []string{"ee"},
	Short:   "activate agent",
	Long:    `activate agent in an appliance`,
	Run:     activateAgentCobra,
	Args:    cobra.ExactArgs(1),
}

func activateAgentCobra(cmd *cobra.Command, args []string) {
	activateAgent(
		args[0],
		viper.GetString("target"),
		viper.GetBool("force"),
		viper.GetBool("replace-config"),
		viper.GetBool("activate-samples"))
}

func activateAgent(
	ee string,
	target string,
	force bool,
	replaceConfig bool,
	activateSamples bool,
) {
	err := client.Client().ActivateExecEnv(id_or_name, ee, target, force, replaceConfig, activateSamples)
	if err != nil {
		client.Error(err)
		return
	}

	if err != nil {
		client.Error(err)
	}
}

func init() {
	activateCmd.AddCommand(activateAgentCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// appliancesCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	activateAgentCmd.Flags().StringP("target", "t", "", "Exec env target folder")
	activateAgentCmd.Flags().BoolP("force", "f", false, "Force activation")
	activateAgentCmd.Flags().BoolP("replace-config", "r", false, "Overwrite exec env configuration")
	activateAgentCmd.Flags().BoolP("install-samples", "s", false, "Install samples")
}
