/*
Copyright © 2022 Sebastian Gonzalez Oyuela sgonzalez@atricore.com

*/
package cmd

import (
	"errors"
	"fmt"
	"os"

	cli "github.com/atricore/josso-cli-go/cli"

	api "github.com/atricore/josso-api-go"
	sdk "github.com/atricore/josso-sdk-go"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile    string
	verbose    bool
	id_or_name string
	client     cli.Cli
	print_raw  bool
	quiet      bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "jossoctl",
	Short: "JOSSO EE control",
	Long:  `JOSSO EE is an IAM platform. This is the command line interface application`,
	// Run before any sub-command
	PersistentPreRunE: preRunE,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func ExecuteJosso() {
	rootCmd.Use = "jossoctl"
	rootCmd.Short = "JOSSO EE control"
	rootCmd.Long = `JOSSO EE is an IAM platform. This is the command line interface application`

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
func ExecuteIamtf() {
	rootCmd.Use = "iamtfctl"
	rootCmd.Short = "IAM.tf control"
	rootCmd.Long = `IAM.tf is an IAM platform. This is the command line interface application`

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

// Initializes the client for all commands
func preRunE(cmd *cobra.Command, args []string) error {

	var err error

	if verbose {
		fmt.Println("configuration:")
		for k, v := range viper.AllSettings() {
			fmt.Printf(" - %s:%v\n", k, v)
		}
	}

	cfg := sdk.IdbusServer{
		Config: &api.ServerConfiguration{
			URL:         viper.Get("endpoint").(string),
			Description: "JOSSO server",
		},
		Credentials: &sdk.ServerCredentials{
			ClientId: viper.Get("client_id").(string),
			Secret:   viper.Get("secret").(string),
		},
	}

	id_or_name = viper.Get("appliance").(string)

	quiet = viper.Get("quiet").(bool)

	client, err = cli.CreateClient(&cfg)

	if err != nil {
		printError(err)
		os.Exit(1)
	}

	return nil
}

func printError(err error) {
	fmt.Printf("ERROR: %v\n", err)
}

func printOut(str string) {
	fmt.Printf("%s\n", str)
}

func init() {

	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.josso-cli-go.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	rootCmd.PersistentFlags().StringP("endpoint", "e", "", "josso server endpoint")
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "enable client debug")
	rootCmd.PersistentFlags().BoolP("trace", "", false, "trace api traffic")
	rootCmd.PersistentFlags().BoolP("quiet", "", false, "quiet")
	rootCmd.PersistentFlags().StringP("client-id", "", "", "client id")
	rootCmd.PersistentFlags().StringP("client-secret", "", "", "client secret")
	rootCmd.PersistentFlags().StringP("client-user", "", "", "josso user")
	rootCmd.PersistentFlags().StringP("client-password", "", "", "josso user password")

	rootCmd.PersistentFlags().StringVarP(&id_or_name, "appliance", "a", "", "Appliance id or name")

	viper.SetEnvPrefix("JOSSO_API")

	// global flags

	viper.BindEnv("appliance")
	viper.BindPFlag("appliance", rootCmd.PersistentFlags().Lookup("appliance"))

	viper.BindEnv("endpoint")
	viper.BindPFlag("endpoint", rootCmd.PersistentFlags().Lookup("endpoint"))
	viper.SetDefault("endpoint", "http://localhost:8081/atricore-rest/services")

	viper.BindEnv("client_id")
	viper.BindPFlag("client_id", rootCmd.PersistentFlags().Lookup("client-id"))

	viper.BindEnv("secret")
	viper.BindPFlag("secret", rootCmd.PersistentFlags().Lookup("client-secret"))

	viper.BindEnv("username")
	viper.BindPFlag("username", rootCmd.PersistentFlags().Lookup("client-user"))
	viper.SetDefault("username", "admin")

	viper.BindEnv("password")
	viper.BindPFlag("password", rootCmd.PersistentFlags().Lookup("client-password"))

	viper.BindEnv("debug")
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))
	viper.SetDefault("debug", false)

	viper.BindEnv("trace")
	viper.BindPFlag("trace", rootCmd.PersistentFlags().Lookup("trace"))
	viper.SetDefault("trace", false)

	viper.BindEnv("quiet")
	viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))
	viper.SetDefault("quiet", false)

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {

	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".cobra" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".josso-cli")

	}

	viper.AutomaticEnv()

	err := viper.ReadInConfig()

	notFound := &viper.ConfigFileNotFoundError{}
	switch {
	case err != nil && !errors.As(err, notFound):
		cobra.CheckErr(err)
	case err != nil && errors.As(err, notFound):
		// The config file is optional, we shouldn't exit when the config is not found
		break
	default:
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
