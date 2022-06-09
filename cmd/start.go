/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/spf13/cobra"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "start an identity appliance",
	Long: `Start an identity appliance.
	
	Depending on the appliance state, several actions may be required like building and deploying`,
	Args: cobra.ExactArgs(1),
	Run:  startApplianceCobra,
}

func startApplianceCobra(cmd *cobra.Command, args []string) {
	startAppliance(args[0])
}

func startAppliance(a string) {
	err := client.Client().StartAppliance(a)
	if err != nil {
		printError(err)
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
