package azure

import (
	"net"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/core/http"
	"github.com/Azure/azure-sdk-for-go/core/tls"
)

// ClientPool manages a set of HTTP clients for processing. A new Client is
// created for every different timeout options that is specified.
// Clients and Transports are safe for concurrent use by multiple
// goroutines and for efficiency should only be created once and re-used.
type ClientPool struct {
	mtx       sync.RWMutex
	transport http.RoundTripper
	tlsConfig *tls.Config
	clients   map[time.Duration]*http.Client
}

// SetTransport sets the transport to be shared by all the clients in the
// pool. If nil, a default transport will be used. The default transport
// will use the same settings as the default one in the core http package
// plus the default TLS Configuration maintained in the pool.
func (c *ClientPool) SetTransport(transport http.RoundTripper) {
	c.mtx.Lock()
	{
		c.transport = transport

		// Ensuring that new clients requested from the pool will use
		// the new transport settings.
		c.clients = make(map[time.Duration]*http.Client)
	}
	c.mtx.Unlock()
}

// SetDefaultTLSConfig sets the TLS Configuration that will be used
// by the default transport. A default transport will be used if no
// transport has been specified.
func (c *ClientPool) SetDefaultTLSConfig(tlsConfig *tls.Config) {
	c.mtx.Lock()
	{
		c.tlsConfig = tlsConfig

		// Ensuring that new clients requested from the pool will use
		// the new transport settings.
		c.clients = make(map[time.Duration]*http.Client)
	}
	c.mtx.Unlock()
}

// GetClient returns a HTTP Client for making HTTP calls based
// on the specified timeout.
func (c *ClientPool) GetClient(timeout time.Duration) *http.Client {
	// Locate a client for this timeout.
	c.mtx.RLock()
	{
		if client := c.clients[timeout]; client != nil {
			c.mtx.RUnlock()
			return client
		}
	}
	c.mtx.RUnlock()

	// Create a new client for this timeout if one did not exist.
	var client *http.Client

	c.mtx.Lock()
	{
		// Check again to be safe now that we are in the write lock.
		if client = c.clients[timeout]; client == nil {
			transport := c.transport
			if transport == nil {
				// Create our own transport using the same settings as
				// the default one in the core http package plus the
				// default TLS Configuration maintained in the pool.
				// This maintains a pool of connections.
				transport = &http.Transport{
					Proxy:           http.ProxyFromEnvironment,
					TLSClientConfig: c.tlsConfig,
					Dial: (&net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 30 * time.Second,
					}).Dial,
					TLSHandshakeTimeout: 10 * time.Second,
				}
			}

			// Create a new Client to use this transport
			// for this specific timeout.
			client = &http.Client{
				Transport: transport,
				Timeout:   timeout,
			}

			// Save this client to the map.
			c.clients[timeout] = client
		}
	}
	c.mtx.Unlock()

	return client
}

// NewClientPool returns a new, empty ClientPool.
func NewClientPool() *ClientPool {
	return &ClientPool{
		clients: make(map[time.Duration]*http.Client),
	}
}

// DefaultClientPool represents the default pool for managing HTTP Clients.
var DefaultClientPool = NewClientPool()
