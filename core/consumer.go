package core

import (
	"time"

	"github.com/Shopify/sarama"
	cluster "github.com/bsm/sarama-cluster"
	"github.com/spf13/viper"
)

// NewConsumer return an event bus with poke-scheduler events
func NewConsumer() (*cluster.Consumer, error) {

	config := cluster.NewConfig()
	config.Consumer.Return.Errors = true
	config.Group.Return.Notifications = true
	config.Config.Net.TLS.Enable = true
	config.Config.Net.SASL.Enable = true
	config.Config.Net.SASL.User = viper.GetString("kafka.user")
	config.Config.Net.SASL.Password = viper.GetString("kafka.password")
	config.ClientID = "poke.ssl-checker"
	config.Consumer.Offsets.Initial = sarama.OffsetOldest
	config.Consumer.Offsets.CommitInterval = 10 * time.Second

	consumerGroup := config.Config.Net.SASL.User + "." + viper.GetString("host")
	brokers := viper.GetStringSlice("kafka.brokers")
	topics := viper.GetStringSlice("kafka.topics")

	consumer, err := cluster.NewConsumer(brokers, consumerGroup, topics, config)
	if err != nil {
		return nil, err
	}

	return consumer, nil
}
