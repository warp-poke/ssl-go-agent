package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/warp-poke/ssl-go-agent/core"
)

var cfgFile string
var verbose bool

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file to use")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	viper.BindPFlags(RootCmd.Flags())
}

func initConfig() {
	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	// Bind environment variables
	viper.SetEnvPrefix("poke_ssl_agent")
	viper.AutomaticEnv()

	// Set config search path
	viper.AddConfigPath("/etc/poke-ssl-agent/")
	viper.AddConfigPath("$HOME/.poke-ssl-agent")
	viper.AddConfigPath(".")

	// Load config
	viper.SetConfigName("config")
	if err := viper.MergeInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Debug("No config file found")
		} else {
			log.Panicf("Fatal error in config file: %v \n", err)
		}
	}

	// Load user defined config
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		err := viper.ReadInConfig()
		if err != nil {
			log.Panicf("Fatal error in config file: %v \n", err)
		}
	}
}

// RootCmd launch the aggregator agent.
var RootCmd = &cobra.Command{
	Use:   "poke-ssl-agent",
	Short: "poke-ssl-agent collect SSL domains stats",
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("poke-ssl-agent starting")

		schedulerEvents := core.NewConsumer()

		//quit := make(chan os.Signal)
		//signal.Notify(quit, os.Interrupt)

		for {
			select {
			case se := <-schedulerEvents:
				log.WithFields(log.Fields{
					"event": se,
				}).Info("process new scheduler event")
				if err := core.Process(se); err != nil {
					log.WithError(err).Error("Failed to process scheduler event")
					continue
				}
				// commit offset

				//case sig := <-quit:
				//	log.Errorf("Got %s signal. Aborting...\n", sig)
				//	os.Exit(1)
			}
		}
	},
}
