/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/spf13/cobra"
)

var (
	start bool
)

// deployCmd represents the deploy command
var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "deploy identity appliance",
	Long:  `deploy identity appliance.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Read start flag
		start, _ := cmd.Flags().GetBool("start")
		DeployAppliance(id_or_name, start)
	},
}

// Deploy appiance function
func DeployAppliance(id_or_name string, start bool) {
	/*
		// Depploy appliance using cli
		err := client.Client().DeployAppliance(a)

		// if no error , start if requested
		if err != nil && start {
			StartAppliance(id_or_name)
		}
	*/
}

func init() {
	rootCmd.AddCommand(deployCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	deployCmd.Flags().BoolP("start", "s", false, "Start appliance after deploy")
}
