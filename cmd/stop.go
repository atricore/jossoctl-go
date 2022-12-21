/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// stopCmd represents the stop command
var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the identity appliance",
	Long:  `Stop the identity appliance`,
	Run:   stopApplianceCobra,
	Args:  cobra.ExactArgs(0),
}

func init() {
	rootCmd.AddCommand(stopCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func stopApplianceCobra(cmd *cobra.Command, args []string) {
	StopAppliance(id_or_name)
}

func StopAppliance(a string) {
	err := client.Client().StopAppliance(a)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
}
