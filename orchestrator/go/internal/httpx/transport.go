// Package httpx provides a shared, connection-pool-tuned HTTP transport for
// the orchestrator's middleware clients. The default transport keeps only 2
// idle connections per host, which forces a fresh TCP+TLS handshake per
// request under concurrency to Keycloak/Permify/Dapr/APISIX.
package httpx

import (
	"net"
	"net/http"
	"sync"
	"time"
)

var (
	shared     *http.Transport
	sharedOnce sync.Once
)

// SharedTransport returns the process-wide tuned transport. Transports are
// safe for concurrent use and designed to be shared across clients.
func SharedTransport() *http.Transport {
	sharedOnce.Do(func() {
		shared = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          200,
			MaxIdleConnsPerHost:   64,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	})
	return shared
}
