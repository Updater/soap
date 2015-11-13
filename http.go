package soap

import (
	"crypto/x509"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/core/http"
	"github.com/Azure/azure-sdk-for-go/core/tls"
)

// pool manages a set of HTTP clients for processing. A new Client is
// created for every different timeout options that is specified.
// Clients and Transports are safe for concurrent use by multiple
// goroutines and for efficiency should only be created once and re-used.
type pool struct {
	mtx       sync.RWMutex
	tlsConfig *tls.Config
	m         map[time.Duration]*http.Client
}

// SetTLSConfig is called to set the TLS Configuration
// to be shared by all the HTTP Clients.
func (p *pool) SetTLSConfig(certProvFile string, certFile string, keyFile string) error {
	var pool *x509.CertPool
	var certs []tls.Certificate

	if certProvFile != "" {
		cpf, err := ioutil.ReadFile(certProvFile)
		if err != nil {
			return err
		}

		pool = x509.NewCertPool()
		pool.AppendCertsFromPEM(cpf)
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}

		certs = []tls.Certificate{cert}
	}

	var tlsConfig *tls.Config
	if pool != nil || len(certs) > 0 {
		tlsConfig = &tls.Config{
			RootCAs:      pool,
			MinVersion:   tls.VersionTLS10, // Avoid fallback to SSL protocols < TLS1.0.
			MaxVersion:   tls.VersionTLS10,
			Certificates: certs,
		}
	}

	p.mtx.Lock()
	{
		p.tlsConfig = tlsConfig
	}
	p.mtx.Unlock()

	return nil
}

// GetClient returns a HTTP client for making HTTP calls.
func (p *pool) GetClient(timeout time.Duration) *http.Client {
	// Locate a client for this timeout.
	p.mtx.RLock()
	{
		if client := p.m[timeout]; client != nil {
			p.mtx.RUnlock()
			return client
		}
	}
	p.mtx.RUnlock()

	// Create a new client for this timeout if one did not exist.
	var client *http.Client

	p.mtx.Lock()
	{
		// Check again to be safe now that we are in the write lock.
		if client = p.m[timeout]; client == nil {
			// Create our own transport using the same settings as the
			// default one. This maintains a pool of connections.
			transport := http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: p.tlsConfig,
				Dial: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).Dial,
				TLSHandshakeTimeout: 10 * time.Second,
			}

			// Create a new Client to use this transport
			// for this specific timeout.
			client = &http.Client{
				Transport: &transport,
				Timeout:   timeout,
			}

			// Save this client to the map.
			p.m[timeout] = client
		}
	}
	p.mtx.Unlock()

	return client
}

// httpPool represents a pool for managing HTTP Clients.
var httpPool = &pool{
	m: make(map[time.Duration]*http.Client),
}
