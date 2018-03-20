package models

// SchedulerEvent is send from Poke scheduler when a check should be perform on a domain
type SchedulerEvent struct {
	Domain         string `json:"domain"`
	Warp10Endpoint string `json:"warp10_endpoint"`
	Token          string `json:"token"`
}
