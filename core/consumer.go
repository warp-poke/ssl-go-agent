package core

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Shopify/sarama"
	cluster "github.com/bsm/sarama-cluster"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/warp-poke/ssl-go-agent/models"
)

// NewConsumer return an event bus with poke-scheduler events
func NewConsumer() <-chan *models.SchedulerEvent {
	se := make(chan *models.SchedulerEvent)

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

	//TEST
	go func() {
		t := time.NewTimer(10 * time.Second)
		<-t.C
		se <- &models.SchedulerEvent{
			Domain:         "clever-cloud.com",
			Warp10Endpoint: "https://gra1-poke.metrics.ovh.net",
			Token:          "TEST",
		}
	}()

	consumer, err := cluster.NewConsumer(brokers, consumerGroup, topics, config)
	if err != nil {
		log.Panic(err)
	}

	go func() {

		for {
			select {
			case m, ok := <-consumer.Messages():
				var ev models.SchedulerEvent
				if err = json.Unmarshal(m.Value, &ev); err != nil {
					log.WithError(err).Error("Cannot unmarshal Scheduler event")
					continue
				}
				se <- &ev
				consumer.MarkOffset(m, "")

				if !ok {
					break
				}

			case err := <-consumer.Errors():
				log.WithError(err).Error("Kafka consumer error")

			case notif := <-consumer.Notifications():
				log.Info(fmt.Sprintf("%+v", notif))

			}
		}
	}()

	return se
}
