/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"github.com/spf13/cobra"
)

// disposeCmd represents the dispose command
var disposeCmd = &cobra.Command{
	Use:   "dispose",
	Short: "dispose identity appliance",
	Long:  `dispose identity appliance.`,
	Run: func(cmd *cobra.Command, args []string) {
		remove, _ := cmd.Flags().GetBool("remove")
		DisposeAppliance(id_or_name, remove)
	},
}

func DisposeAppliance(id_or_name string, remove bool) {
	/*
		// Dispose appliance using cli
		err := client.Client().DisposeAppliance(a)

		// if no error , remove if requested
		if err != nil && remove {
			RemoveAppliance(id_or_name)
		}
	*/
}

func init() {
	rootCmd.AddCommand(disposeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	disposeCmd.Flags().BoolP("remove", "r", false, "Also remove the appliance")
}
