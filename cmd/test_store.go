/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// TestStoreCmd represents the TestStore command
var testStoreCmd = &cobra.Command{
	Use:   "test store",
	Short: "test store identity appliance",
	Long:  `Test Store identity appliance.`,
	Args:  cobra.ExactArgs(1), // Id source name
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO!")
	},
}

func init() {
	testCmd.AddCommand(testStoreCmd)

}
