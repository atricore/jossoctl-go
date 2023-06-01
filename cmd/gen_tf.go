package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Import represents the Import command
var genTFCmd = &cobra.Command{
	Use:     "generate-tf",
	Aliases: []string{"tf"},
	Short:   "generate terraform resource file",
	Args:    cobra.ExactArgs(1),
	Long:    `Generate empty terraform resource file so you can use terraform import later.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TODO : Generate all TF resoruces")
	},
}

var fName, outputType string
var replace bool

func init() {
	rootCmd.AddCommand(genTFCmd)
	genTFCmd.PersistentFlags().BoolVarP(&replace, "replace", "r", false, "Replace output file if it exists")
	genTFCmd.PersistentFlags().StringVarP(&outputType, "output-type", "t", "stdout", "Output type (file or stdout)")
	genTFCmd.PersistentFlags().StringVarP(&fName, "file", "f", "", "Store the output in the given file name")
}
