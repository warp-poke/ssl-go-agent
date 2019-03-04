package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/warp-poke/ssl-go-agent/core"
	"github.com/warp-poke/ssl-go-agent/models"
)

func init() {
	prometheus.MustRegister(eventsCounter)
	prometheus.MustRegister(eventsSchedulerErrorCounter)
	prometheus.MustRegister(eventsErrorCounter)
	prometheus.MustRegister(eventsKafkaConsumerErrorCounter)
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().StringP("config", "", "", "config file to use")
	RootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")

	viper.BindPFlags(RootCmd.Flags())
}

func initConfig() {
	if viper.GetBool("verbose") {
		log.SetLevel(log.DebugLevel)
	}

	// Bind environment variables
	viper.SetEnvPrefix("poke_ssl_agent")
	viper.SetEnvKeyReplacer(strings.NewReplacer("_", "."))
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
	cfgFile := viper.GetString("config")
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		err := viper.ReadInConfig()
		if err != nil {
			log.Panicf("Fatal error in config file: %v \n", err)
		}
	}
}

var (
	eventsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "ssl",
		Subsystem: "agent",
		Name:      "events",
		Help:      "Number of events handled",
	})

	eventsErrorCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "ssl",
		Subsystem: "agent",
		Name:      "error_events",
		Help:      "Number of events in error",
	})

	eventsKafkaConsumerErrorCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "ssl",
		Subsystem: "agent",
		Name:      "kafka_error_events",
		Help:      "Number of events causing kafka consumer error",
	})

	eventsSchedulerErrorCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "ssl",
		Subsystem: "agent",
		Name:      "scheduler_error_events",
		Help:      "Number of events causing scheduler error",
	})
)

// RootCmd launch the aggregator agent.
var RootCmd = &cobra.Command{
	Use:   "poke-ssl-agent",
	Short: "poke-ssl-agent collect SSL domains stats",
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("poke-ssl-agent starting")

		http.Handle("/metrics", promhttp.Handler())
		err := http.ListenAndServe(":2112", nil)

		if err != nil {
			log.WithError(err).Fatal("Fail to open prometheus Handler")
		}

		quit := make(chan os.Signal, 2)
		signal.Notify(quit, syscall.SIGTERM)
		signal.Notify(quit, syscall.SIGINT)

		consumer, err := core.NewConsumer()
		if err != nil {
			log.WithError(err).Fatal("Could not start the kafka consumer")
		}

		for {
			select {
			case m, ok := <-consumer.Messages():
				if !ok {
					log.Fatal("Kafka stream was closed")
				}

				var ev models.SchedulerEvent
				if err := json.Unmarshal(m.Value, &ev); err != nil {
					eventsErrorCounter.Inc()
					log.WithError(err).Error("Cannot unmarshal scheduler event")
					continue
				}

				go func() {
					log.WithField("event", ev).Info("process new scheduler event")
					if err := core.Process(&ev); err != nil {
						eventsSchedulerErrorCounter.Inc()
						log.WithError(err).Error("Failed to process scheduler event")
						return
					}

					consumer.MarkOffset(m, "")
				}()

			case err := <-consumer.Errors():
				eventsKafkaConsumerErrorCounter.Inc()
				log.WithError(err).Error("Kafka consumer error")

			case notif := <-consumer.Notifications():
				eventsCounter.Inc()
				log.Info(fmt.Sprintf("%+v", notif))
			case <-quit:
				log.Info("ssl-go-agent halted!")
				return
			}
		}
	},
}
