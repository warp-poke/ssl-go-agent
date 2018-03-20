package models

import (
	"time"
)

// Result of an SSL test to send on Warp10
type Result struct {
	Grade          string    `json:"grade"`
	ExpirationDate time.Time `json:"expirationDate"`
}
