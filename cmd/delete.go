/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// deleteCmd represents the remove command
var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete identity appliance",
	Long:  `Remove identity appliance from the server.`,
	Run:   deleteApplianceCobra,
}

func init() {
	rootCmd.AddCommand(deleteCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// stopCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func deleteApplianceCobra(cmd *cobra.Command, args []string) {
	if len(args) > 0 {
		DeleteAppliance(args[0])
	} else {
		DeleteAppliance(id_or_name)
	}
}

func DeleteAppliance(a string) {
	del, err := client.Client().DeleteAppliance(a)
	if err != nil {
		printError(err)
		os.Exit(1)
	}

	if !del {
		printError(fmt.Errorf("appliance %s not deleted", a))
		os.Exit(1)
	}

}
