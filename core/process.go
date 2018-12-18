package core

import (
	"time"

	warp "github.com/miton18/go-warp10/base"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/warp-poke/ssl-go-agent/models"
)

// Process perform SSL test and return metrics
func Process(e *models.SchedulerEvent) error {
	domainInfos, err := GetSSLInfos(e.Domain)
	if err != nil {
		return err
	}

	testDate := time.Now().Unix() * 1000 * 1000
	client := warp.NewClient(e.Warp10Endpoint)
	client.WriteToken = e.Token

	grade := warp.NewGTSWithLabels("http.ssl.grade", warp.Labels{
		"domain": e.Domain,
		"host":   viper.GetString("host"),
		"zone":   viper.GetString("zone"),
	})

	grade.Values = [][]interface{}{{testDate, domainInfos.Grade}}
	log.WithFields(log.Fields{
		"metric": grade.Sensision(),
	}).Debug("New grade metric")

	expiration := warp.NewGTSWithLabels("http.ssl.valid.until", warp.Labels{
		"domain": e.Domain,
		"host":   viper.GetString("host"),
		"zone":   viper.GetString("zone"),
	})

	expiration.Values = [][]interface{}{{testDate, domainInfos.ExpirationDate.Unix() * 1000 * 1000}}
	log.WithFields(log.Fields{
		"metric": expiration.Sensision(),
	}).Debug("New expiration metric")

	return client.Update(warp.GTSList{grade, expiration})
}
