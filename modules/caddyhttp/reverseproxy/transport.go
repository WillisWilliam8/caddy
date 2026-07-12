// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reverseproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"golang.org/x/net/http2"
)

func init() {
	caddy.RegisterModule(HTTPTransport{})
}

// HTTPTransport is a transport that uses HTTP.
type HTTPTransport struct {
	DialTimeout           caddy.Duration `json:"dial_timeout,omitempty"`
	DialKeepAlive         caddy.Duration `json:"dial_keep_alive,omitempty"`
	MaxConnsPerHost       int            `json:"max_conns_per_host,omitempty"`
	MaxIdleConns          int            `json:"max_idle_conns,omitempty"`
	MaxIdleConnsPerHost   int            `json:"max_idle_conns_per_host,omitempty"`
	IdleConnTimeout       caddy.Duration `json:"idle_conn_timeout,omitempty"`
	ResponseHeaderTimeout caddy.Duration `json:"response_header_timeout,omitempty"`
	ExpectContinueTimeout caddy.Duration `json:"expect_continue_timeout,omitempty"`
	MaxResponseHeaderSize int64          `json:"max_response_header_size,omitempty"`
	WriteBufferSize       int            `json:"write_buffer_size,omitempty"`
	ReadBufferSize        int            `json:"read_buffer_size,omitempty"`

	// TLS-related settings
	TLS *TLSConfig `json:"tls,omitempty"`

	// KeepAliveIdleTimeout is the duration after which an idle connection
	// will be closed.
	// Deprecated: Use IdleConnTimeout instead.
	KeepAliveIdleTimeout caddy.Duration `json:"keep_alive_idle_timeout,omitempty"`

	// HTTP2 enables HTTP/2 support.
	// Deprecated: HTTP/2 is now enabled by default.
	// TODO: remove this field
	HTTP2 *bool `json:"http2,omitempty"`

	// ReadIdleTimeout is the flow-control/keep-alive timeout for HTTP/2 connections.
	ReadIdleTimeout caddy.Duration `json:"read_idle_timeout,omitempty"`

	// PingTimeout is the timeout for HTTP/2 PING frames.
	PingTimeout caddy.Duration `json:"ping_timeout,omitempty"`

	// Retries is the number of times to retry a request if it fails due to a
	// stale connection or TLS handshake error.
	Retries int `json:"retries,omitempty"`

	transport *http.Transport
}

// CaddyModule returns the Caddy module information.
func (HTTPTransport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.transport.http",
		New: func() caddy.Module { return new(HTTPTransport) },
	}
}

// Provision sets up the transport.
func (h *HTTPTransport) Provision(ctx caddy.Context) error {
	dialer := &net.Dialer{
		Timeout:   time.Duration(h.DialTimeout),
		KeepAlive: time.Duration(h.DialKeepAlive),
	}

	h.transport = &http.Transport{
		DialContext:           dialer.DialContext,
		MaxConnsPerHost:       h.MaxConnsPerHost,
		MaxIdleConns:          h.MaxIdleConns,
		MaxIdleConnsPerHost:   h.MaxIdleConnsPerHost,
		IdleConnTimeout:       time.Duration(h.IdleConnTimeout),
		ResponseHeaderTimeout: time.Duration(h.ResponseHeaderTimeout),
		ExpectContinueTimeout: time.Duration(h.ExpectContinueTimeout),
		MaxResponseHeaderSize: h.MaxResponseHeaderSize,
		WriteBufferSize:       h.WriteBufferSize,
		ReadBufferSize:        h.ReadBufferSize,
	}

	if h.KeepAliveIdleTimeout > 0 {
		h.transport.IdleConnTimeout = time.Duration(h.KeepAliveIdleTimeout)
	}

	if h.TLS != nil {
		tlsConfig, err := h.TLS.toTLSConfig(ctx)
		if err != nil {
			return err
		}
		h.transport.TLSClientConfig = tlsConfig
	}

	if h.HTTP2 == nil || *h.HTTP2 {
		h2Trans, err := http2.ConfigureTransports(h.transport)
		if err != nil {
			return fmt.Errorf("configuring HTTP/2 transport: %v", err)
		}
		if h.ReadIdleTimeout > 0 {
			h2Trans.ReadIdleTimeout = time.Duration(h.ReadIdleTimeout)
		}
		if h.PingTimeout > 0 {
			h2Trans.PingTimeout = time.Duration(h.PingTimeout)
		}
	}

	return nil
}

// RoundTrip implements http.RoundTripper.
func (h *HTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	maxRetries := h.Retries
	if maxRetries <= 0 {
		maxRetries = 2 // default to 2 retries
	}

	var resp *http.Response
	var err error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 && req.Body != nil {
			if req.GetBody != nil {
				newBody, bodyErr := req.GetBody()
				if bodyErr != nil {
					return nil, bodyErr
				}
				req.Body = newBody
			} else {
				break
			}
		}

		resp, err = h.transport.RoundTrip(req)
		if err == nil {
			return resp, nil
		}

		if isStaleConnectionError(err) {
			h.transport.CloseIdleConnections()
			continue
		}

		break
	}

	return resp, err
}

func isStaleConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	if strings.Contains(errStr, "tls: bad record MAC") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "EOF") ||
		strings.Contains(errStr, "GOAWAY") ||
		strings.Contains(errStr, "http2: server sent GOAWAY") ||
		strings.Contains(errStr, "stream error") ||
		strings.Contains(errStr, "tls: use of closed connection") {
		return true
	}
	return false
}

// Cleanup cleans up the transport.
func (h *HTTPTransport) Cleanup() error {
	h.transport.CloseIdleConnections()
	return nil
}

// TLSConfig holds TLS-related configuration for the transport.
type TLSConfig struct {
	RootPEMFiles             []string       `json:"root_pem_files,omitempty"`
	ClientCertificateFile    string         `json:"client_certificate_file,omitempty"`
	ClientCertificateKeyFile string         `json:"client_certificate_key_file,omitempty"`
	InsecureSkipVerify       bool           `json:"insecure_skip_verify,omitempty"`
	HandshakeTimeout         caddy.Duration `json:"handshake_timeout,omitempty"`
	ServerName               string         `json:"server_name,omitempty"`
}

func (t *TLSConfig) toTLSConfig(ctx caddy.Context) (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: t.InsecureSkipVerify,
		ServerName:         t.ServerName,
	}

	if len(t.RootPEMFiles) > 0 {
		pool := x509.NewCertPool()
		for _, file := range t.RootPEMFiles {
			pemBytes, err := os.ReadFile(file)
			if err != nil {
				return nil, fmt.Errorf("reading root PEM file %s: %v", file, err)
			}
			if !pool.AppendCertsFromPEM(pemBytes) {
				return nil, fmt.Errorf("failed to parse root PEM file %s", file)
			}
		}
		cfg.RootCAs = pool
	}

	if t.ClientCertificateFile != "" && t.ClientCertificateKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(t.ClientCertificateFile, t.ClientCertificateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %v", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// UnmarshalCaddyfile deserializes Caddyfile tokens into h.
func (h *HTTPTransport) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "dial_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid dial_timeout: %v", err)
				}
				h.DialTimeout = caddy.Duration(dur)

			case "dial_keepalive":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid dial_keepalive: %v", err)
				}
				h.DialKeepAlive = caddy.Duration(dur)

			case "max_conns_per_host":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid max_conns_per_host: %v", err)
				}
				h.MaxConnsPerHost = val

			case "max_idle_conns":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid max_idle_conns: %v", err)
				}
				h.MaxIdleConns = val

			case "max_idle_conns_per_host":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid max_idle_conns_per_host: %v", err)
				}
				h.MaxIdleConnsPerHost = val

			case "idle_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid idle_timeout: %v", err)
				}
				h.IdleConnTimeout = caddy.Duration(dur)

			case "response_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid response_timeout: %v", err)
				}
				h.ResponseHeaderTimeout = caddy.Duration(dur)

			case "expect_continue_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid expect_continue_timeout: %v", err)
				}
				h.ExpectContinueTimeout = caddy.Duration(dur)

			case "read_idle_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid read_idle_timeout: %v", err)
				}
				h.ReadIdleTimeout = caddy.Duration(dur)

			case "ping_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid ping_timeout: %v", err)
				}
				h.PingTimeout = caddy.Duration(dur)

			case "retries":
				if !d.NextArg() {
					return d.ArgErr()
				}
				val, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid retries: %v", err)
				}
				h.Retries = val

			case "tls":
				if h.TLS == nil {
					h.TLS = new(TLSConfig)
				}
				for d.NextBlock(1) {
					switch d.Val() {
					case "root_pem_file":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.TLS.RootPEMFiles = append(h.TLS.RootPEMFiles, d.Val())
					case "client_certificate_file":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.TLS.ClientCertificateFile = d.Val()
					case "client_certificate_key_file":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.TLS.ClientCertificateKeyFile = d.Val()
					case "insecure_skip_verify":
						h.TLS.InsecureSkipVerify = true
					case "handshake_timeout":
						if !d.NextArg() {
							return d.ArgErr()
						}
						dur, err := caddy.ParseDuration(d.Val())
						if err != nil {
							return d.Errf("invalid handshake_timeout: %v", err)
						}
						h.TLS.HandshakeTimeout = caddy.Duration(dur)
					case "server_name":
						if !d.NextArg() {
							return d.ArgErr()
						}
						h.TLS.ServerName = d.Val()
					default:
						return d.Errf("unrecognized tls option '%s'", d.Val())
					}
				}
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*HTTPTransport)(nil)
	_ caddy.Cleaner         = (*HTTPTransport)(nil)
	_ http.RoundTripper     = (*HTTPTransport)(nil)
	_ caddyfile.Unmarshaler = (*HTTPTransport)(nil)
)