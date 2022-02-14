package main

import "github.com/arielril/oauth2-ms365-sample/log"

var logger = log.GetInstance()

func main() {
	logger.Info().Msg("sup")
}
