package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/warp-poke/ssl-go-agent/models"
)

// GetSSLInfos Return SSL informnations for a domain
func GetSSLInfos(domain string) (*models.Result, error) {
	m := NewManager(NewHostProvider([]string{domain}))

	for {
		_, running := <-m.FrontendEventChannel
		if running == false {
			if len(m.results.responses) != 1 {
				return nil, errors.New("Mismatch result length and domains to check")
			}

			var result models.SSLLabsResponse
			if err := json.Unmarshal([]byte(m.results.responses[0]), &result); err != nil {
				return nil, err
			}

			fmt.Println(m.results.responses[0])
			//log.Info(fmt.Sprintf("%+v", result))
			tm := time.Unix(int64(result.Endpoints[0].Details.Cert.NotAfter/1000), 0)

			return &models.Result{
				Grade:          result.Endpoints[0].Grade,
				ExpirationDate: tm,
			}, nil
		}
	}
}
