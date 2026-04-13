package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type Client struct {
	Secret                string   `json:"secret"`
	SessionID             uint64   `json:"session_id"`
	LocalBind             string   `json:"local_bind"`
	WANBind               string   `json:"wan_bind"`
	Resolvers             []string `json:"resolvers"`
	Domains               []string `json:"domains"`
	FakeSendIP            string   `json:"fake_send_ip"`
	FakeSendPort          int      `json:"fake_send_port"`
	PublicIP              string   `json:"public_ip"`
	PublicIPURL           string   `json:"public_ip_url"`
	MaxQNameLen           int      `json:"max_qname_len"`
	MaxLabelLen           int      `json:"max_label_len"`
	QueryTimeoutMS        int      `json:"query_timeout_ms"`
	KeepaliveFastMS       int      `json:"keepalive_fast_ms"`
	KeepaliveSlowMS       int      `json:"keepalive_slow_ms"`
	InfoRefreshMS         int      `json:"info_refresh_ms"`
	DNSPayloadBytes       int      `json:"dns_payload_bytes"`
	QueueSize             int      `json:"queue_size"`
	ResolverCooldownMS    int      `json:"resolver_cooldown_ms"`
	ResolverFailureWeight float64  `json:"resolver_failure_weight"`
}

type Server struct {
	Secret                 string   `json:"secret"`
	ListenDNS              string   `json:"listen_dns"`
	Domains                []string `json:"domains"`
	UpstreamAddress        string   `json:"upstream_address"`
	DownlinkPayloadBytes   int      `json:"downlink_payload_bytes"`
	SessionTimeoutMS       int      `json:"session_timeout_ms"`
	SpoofTTL               int      `json:"spoof_ttl"`
	UpstreamReadBufferSize int      `json:"upstream_read_buffer_size"`
}

func LoadClient(path string) (Client, error) {
	var cfg Client
	if err := loadJSON(path, &cfg); err != nil {
		return Client{}, err
	}
	cfg.applyDefaults()
	return cfg, cfg.validate()
}

func LoadServer(path string) (Server, error) {
	var cfg Server
	if err := loadJSON(path, &cfg); err != nil {
		return Server{}, err
	}
	cfg.applyDefaults()
	return cfg, cfg.validate()
}

func loadJSON(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func (c *Client) applyDefaults() {
	if c.LocalBind == "" {
		c.LocalBind = "127.0.0.1:10443"
	}
	if c.WANBind == "" {
		c.WANBind = "0.0.0.0:0"
	}
	if c.MaxQNameLen == 0 {
		c.MaxQNameLen = 253
	}
	if c.MaxLabelLen == 0 {
		c.MaxLabelLen = 63
	}
	if c.QueryTimeoutMS == 0 {
		c.QueryTimeoutMS = 1800
	}
	if c.KeepaliveFastMS == 0 {
		c.KeepaliveFastMS = 3000
	}
	if c.KeepaliveSlowMS == 0 {
		c.KeepaliveSlowMS = 12000
	}
	if c.InfoRefreshMS == 0 {
		c.InfoRefreshMS = int((20 * time.Second).Milliseconds())
	}
	if c.QueueSize == 0 {
		c.QueueSize = 1024
	}
	if c.ResolverCooldownMS == 0 {
		c.ResolverCooldownMS = int((5 * time.Second).Milliseconds())
	}
	if c.ResolverFailureWeight == 0 {
		c.ResolverFailureWeight = 2500
	}
}

func (s *Server) applyDefaults() {
	if s.ListenDNS == "" {
		s.ListenDNS = ":53"
	}
	if s.DownlinkPayloadBytes == 0 {
		s.DownlinkPayloadBytes = 900
	}
	if s.SessionTimeoutMS == 0 {
		s.SessionTimeoutMS = int((90 * time.Second).Milliseconds())
	}
	if s.SpoofTTL == 0 {
		s.SpoofTTL = 128
	}
	if s.UpstreamReadBufferSize == 0 {
		s.UpstreamReadBufferSize = 64 * 1024
	}
}

func (c Client) validate() error {
	switch {
	case strings.TrimSpace(c.Secret) == "":
		return fmt.Errorf("secret is required")
	case len(c.Resolvers) == 0:
		return fmt.Errorf("at least one resolver is required")
	case len(c.Domains) == 0:
		return fmt.Errorf("at least one domain is required")
	case c.FakeSendIP == "":
		return fmt.Errorf("fake_send_ip is required")
	case c.FakeSendPort <= 0 || c.FakeSendPort > 65535:
		return fmt.Errorf("fake_send_port must be 1..65535")
	case c.MaxQNameLen < 64 || c.MaxQNameLen > 253:
		return fmt.Errorf("max_qname_len must be within 64..253")
	case c.MaxLabelLen < 8 || c.MaxLabelLen > 63:
		return fmt.Errorf("max_label_len must be within 8..63")
	case c.QueryTimeoutMS < 200:
		return fmt.Errorf("query_timeout_ms must be >= 200")
	case c.KeepaliveFastMS < 500 || c.KeepaliveSlowMS < c.KeepaliveFastMS:
		return fmt.Errorf("invalid keepalive intervals")
	case c.QueueSize < 16:
		return fmt.Errorf("queue_size must be >= 16")
	}
	return nil
}

func (s Server) validate() error {
	switch {
	case strings.TrimSpace(s.Secret) == "":
		return fmt.Errorf("secret is required")
	case len(s.Domains) == 0:
		return fmt.Errorf("at least one domain is required")
	case strings.TrimSpace(s.UpstreamAddress) == "":
		return fmt.Errorf("upstream_address is required")
	case s.DownlinkPayloadBytes < 256:
		return fmt.Errorf("downlink_payload_bytes must be >= 256")
	case s.SessionTimeoutMS < 1000:
		return fmt.Errorf("session_timeout_ms must be >= 1000")
	}
	return nil
}
