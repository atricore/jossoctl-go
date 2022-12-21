/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// buildCmd represents the build command
var buildCmd = &cobra.Command{
	Use:     "build",
	Aliases: []string{"b"},
	Short:   "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		deploy, _ := cmd.Flags().GetBool("deploy")
		BuildAppliance(id_or_name, deploy)
	},
}

func BuildAppliance(id_or_name string, start bool) {
	// build appliance using cli
	err := client.Client().BuildAppliance(id_or_name)
	// if no error , deploy if requested
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	if start {
		StartAppliance(id_or_name)
	}

}

func init() {
	rootCmd.AddCommand(buildCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// buildCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// buildCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	buildCmd.Flags().BoolP("start", "", false, "deploy and start the Identity Appliance")
}
