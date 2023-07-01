package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var serverInfoCmd = &cobra.Command{
	Use:     "info",
	Short:   "shows current server version and node id",
	Aliases: []string{"b"},

	Args: cobra.MaximumNArgs(0),
	Long: `shows the version for the configured server and node id`,
	RunE: func(cmd *cobra.Command, args []string) error {
		info, err := Client.Client().GetInfo()
		if err != nil {
			Client.Error(err)
			os.Exit(1)
		}
		printOut(info.GetVersion() + " (" + info.GetNodeId() + ")")
		return nil

	},
}

func init() {
	serverCmd.AddCommand(serverInfoCmd)
}
