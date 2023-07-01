package cmd

/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/

import (
	"os"

	"github.com/spf13/cobra"

	sdk "github.com/atricore/josso-sdk-go"
)

// listCmd represents the list command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "shows current server version",
	Args:  cobra.MaximumNArgs(0),
	Long:  `shows the version for the configured server`,
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := serverVersion()
		if err != nil {
			Client.Error(err)
			os.Exit(1)
		}
		printOut(v)

		return nil

	},
}

func serverVersion() (string, error) {
	cfg := serverConfig()
	return sdk.ServerVersion(&cfg)
}

func init() {
	rootCmd.AddCommand(serverCmd)
}
