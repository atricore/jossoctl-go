package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "display configuration information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("config file :       [%s]\n", viper.SetConfigName())
		fmt.Printf("config file :       [%s]\n", viper.GetViper().ConfigFileUsed())
		fmt.Printf("endpoint    :       [%s]\n", viper.Get("endpoint").(string))
		fmt.Printf("client id   :       [%s]\n", viper.Get("client_id").(string))
		fmt.Printf("secret      :       [%s]\n", viper.Get("secret").(string))
		fmt.Printf("version     :       [%s]\n", VERSION)
	},
	Annotations: map[string]string{"failOnPreRun": "false"},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
