/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// disposeCmd represents the dispose command
var disposeCmd = &cobra.Command{
	Use:   "dispose",
	Short: "dispose identity appliance",
	Long:  `dispose identity appliance.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO!")
	},
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
}
