/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"
	"os"

	"github.com/atricore/josso-cli-go/util"
	"github.com/spf13/cobra"
)

// deleteCmd represents the remove command
var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete identity appliance",
	Long:  `Remove identity appliance from the server.`,
	Run:   deleteApplianceCobra,
	Args:  cobra.ExactArgs(0),
}

func init() {
	rootCmd.AddCommand(deleteCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// stopCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	deleteCmd.Flags().BoolP("force", "f", false, "Force delete")
}

func deleteApplianceCobra(cmd *cobra.Command, args []string) {

	// get force flag
	force, err := cmd.Flags().GetBool("force")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	printOut("Are you sure you want to delete the appliance? [y/N] ")
	if force || util.AskUser() {
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
