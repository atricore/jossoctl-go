/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "start an identity appliance",
	Long: `Start an identity appliance.
	
	Depending on the appliance state, several actions may be required like building and deploying`,
	Args: cobra.ExactArgs(0),
	Run:  startApplianceCobra,
}

func startApplianceCobra(cmd *cobra.Command, args []string) {
	StartAppliance(id_or_name)
}

func StartAppliance(a string) {
	err := client.Client().StartAppliance(a)
	if err != nil {
		printError(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(startCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// startCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// startCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	//startCmd.Flags().StringP("appliance", "n", false, "Help message for toggle")
	startCmd.Flags().StringVarP(&id_or_name, "name", "n", "", "appliance name")
}
