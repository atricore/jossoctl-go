package cmd

/*
Copyright © 2022 atricore <sgonzalez@atricore.com>

*/

import (
	"os"

	"github.com/spf13/cobra"
)

// listCmd represents the list command
var serverVersionCmd = &cobra.Command{
	Use:   "server-version",
	Short: "shows current server version",
	Args:  cobra.MaximumNArgs(0),
	Long:  `shows the version for the configured server`,
	RunE: func(cmd *cobra.Command, args []string) error {
		v, err := serverVersion()
		if err != nil {
			client.Error(err)
			os.Exit(1)
		}
		printOut(v + "\n")

		return nil

	},
}

func serverVersion() (string, error) {

	return client.Client().ServerVersion()
}

func init() {
	rootCmd.AddCommand(serverVersionCmd)
}
