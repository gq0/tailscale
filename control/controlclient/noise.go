// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/multierr"
)

// noiseClient provides a http.Client to connect to tailcontrol over
// the ts2021 protocol.
type noiseClient struct {
	http.Client // HTTP client used to talk to tailcontrol
	priKey      key.MachinePrivate
	serverKey   key.MachinePublic
	serverURL   string

	mu    sync.Mutex
	conns []*controlbase.Conn // All created connections. TODO(maisem): clean up dead connections.
}

// newNoiseClient returns a new noiseClient for the provided server and machine key.
func newNoiseClient(ctx context.Context, priKey key.MachinePrivate, serverURL string) (*noiseClient, error) {
	np := &noiseClient{
		priKey:    priKey,
		serverURL: serverURL,
	}

	np.Client = http.Client{
		Transport: &http2.Transport{
			DialTLS:   np.Dial,
			AllowHTTP: true,
		},
	}

	return np, nil
}

// Close closes all the underlying noise connections.
// It is a no-op and returns nil if the connection is already closed.
func (nc *noiseClient) Close() error {
	nc.mu.Lock()
	conns := nc.conns
	nc.conns = nil
	nc.mu.Unlock()

	var errors []error
	for _, c := range conns {
		if err := c.Close(); err != nil {
			errors = append(errors, err)
		}
	}
	if len(errors) > 0 {
		return multierr.New(errors...)
	}
	return nil
}

// Dial opens a new connection to tailcontrol, fetching the server noise key
// if not cached. The address is ignored as it only dials the serverURL it was
// created for.
func (nc *noiseClient) Dial(network, _ string, cfg *tls.Config) (net.Conn, error) {
	nc.mu.Lock()
	priKey := nc.priKey
	serverKey := nc.serverKey
	serverURL := nc.serverURL
	nc.mu.Unlock()

	// This context is only used for the dial.
	// Pick an arbitrary timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if serverKey.IsZero() {
		sk, err := loadServerNoiseKey(ctx, http.DefaultClient, serverURL)
		if err != nil {
			return nil, err
		}
		serverKey = sk
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, err
	}
	conn, err := controlhttp.Dial(ctx, u.Host, priKey, serverKey)
	if err != nil {
		return nil, err
	}
	nc.mu.Lock()
	nc.serverKey = serverKey
	nc.conns = append(nc.conns, conn)
	nc.mu.Unlock()
	return conn, nil
}

func loadServerNoiseKey(ctx context.Context, httpc *http.Client, serverURL string) (k key.MachinePublic, _ error) {
	url := fmt.Sprintf("%s/server-key?mapRequestVersion=%d", serverURL, tailcfg.CurrentMapRequestVersion)
	k, err := loadKey(ctx, httpc, url)
	if err != nil {
		return k, fmt.Errorf("failed to get server noise key from %q: %w", url, err)
	}
	return k, nil
}
