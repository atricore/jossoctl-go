/*
Copyright © 2022 atricore <sgonzalez@atricore.com>
*/
package cmd

import (
	"os"

	"github.com/atricore/josso-cli-go/render/formatter"
	"github.com/spf13/cobra"
)

// appliancesCmd represents the appliances command
var listBrandinsCmd = &cobra.Command{
	Use:     "brandings",
	Aliases: []string{"b"},
	Short:   "list brandings",
	Long:    `list UI brandings`,
	Run:     listBrandingsCobra,
	Args:    cobra.MaximumNArgs(0),
}

func listBrandingsCobra(cmd *cobra.Command, args []string) {
	listBrandings()
}

func listBrandings() {
	lsa, err := Client.Client().GetBrandingDefinitionDTOs()
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}

	source := func() string {
		if print_raw {
			return "raw"
		}
		return "table"
	}

	ctx := formatter.BrandingContext{
		Context: formatter.Context{
			Output: Client.Out(),
			Format: formatter.NewBrandingFormat(source(), quiet),
		},
	}
	err = formatter.BrandingWrite(ctx, lsa)
	if err != nil {
		Client.Error(err)
		os.Exit(1)
	}

}

func init() {
	listCmd.AddCommand(listBrandinsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// appliancesCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// appliancesCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
