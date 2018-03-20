package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/warp-poke/ssl-go-agent/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		log.Panicf("%v", err)
	}
}
