package cmd

import (
	"os"

	"github.com/atricore/josso-cli-go/render/formatter"
	"github.com/spf13/cobra"
)

var serverBundlesCmd = &cobra.Command{
	Use:     "bundles",
	Short:   "shows current server version",
	Aliases: []string{"b"},

	Args: cobra.MaximumNArgs(0),
	Long: `shows the version for the configured server`,
	RunE: func(cmd *cobra.Command, args []string) error {
		bundles, err := Client.Client().GetOSGiBundles()
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

		ctx := formatter.OSGiBundleContext{
			Context: formatter.Context{
				Output: Client.Out(),
				Format: formatter.NewOSGiBundleContainerFormat(source(), quiet),
			},
		}
		err = formatter.OSGiBundleWrite(ctx, bundles)
		if err != nil {
			Client.Error(err)
			os.Exit(1)
		}
		return nil

	},
}

func init() {
	serverBundlesCmd.PersistentFlags().BoolVarP(&print_raw, "raw", "r", false, "Display raw content")
	serverCmd.AddCommand(serverBundlesCmd)
}
