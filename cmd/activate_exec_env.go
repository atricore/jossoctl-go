/*
Copyright © 2022 atricore <sgonzalez@atricore.com>
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// appliancesCmd represents the appliances command
var activateAgentCmd = &cobra.Command{
	Use:     "exec-env",
	Aliases: []string{"ee"},
	Short:   "activate agent",
	Long:    `activate agent in an appliance`,
	RunE:    activateAgentCobra,
	Args:    cobra.ExactArgs(1),
}

func activateAgentCobra(cmd *cobra.Command, args []string) error {

	target, err := cmd.Flags().GetString("target")
	if err != nil {
		return err
	}

	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		return err
	}

	replaceConfig, err := cmd.Flags().GetBool("replace-config")
	if err != nil {
		return err
	}

	activateSamples, err := cmd.Flags().GetBool("install-samples")
	if err != nil {
		return err
	}

	activateAgent(
		args[0],
		target,
		force,
		replaceConfig,
		activateSamples)

	return nil
}

func activateAgent(
	ee string,
	target string,
	force bool,
	replaceConfig bool,
	activateSamples bool,
) {

	//fmt.Printf("ee [%s], target [%s], force %t, replace-config %t, activate-samples %t\n", ee, target, force, replaceConfig, activateSamples)
	err := Client.Client().ActivateExecEnv(id_or_name, ee, target, force, replaceConfig, activateSamples)
	if err != nil {
		Client.Error(err)
		return
	}

	if err != nil {
		Client.Error(err)
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
