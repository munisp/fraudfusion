package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
)

func redisTLSConfig() (*tls.Config, error) {
	serverName := strings.TrimSpace(os.Getenv("REDIS_TLS_SERVER_NAME"))
	if serverName == "" {
		return nil, fmt.Errorf("REDIS_TLS_SERVER_NAME is required when Redis TLS is enabled")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}, nil
}
