package types

import (
	"fmt"
	"time"
)

// Host represents one row of the hosts table.
type Host struct {
	Host      string   `json:"host"`
	Root      string   `json:"root"`
	Depth     int      `json:"depth"`
	Sources   string   `json:"sources"`
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	New       bool     `json:"new"`
	Alive     bool     `json:"alive"`
	URL       string   `json:"url"`
	Status    int      `json:"status"`
	Title     string   `json:"title"`
	Server    string   `json:"server"`
	Tech      []string `json:"tech"`
	IPs       string   `json:"ips"`
	CDN       string   `json:"cdn"`
	WAF       string   `json:"waf"`
	Length    int      `json:"length"`
	AuthType  string   `json:"auth_type"`
	AuthURL   string   `json:"auth_url"`
}

// Probe is the subset of an httpx result stored per host.
type Probe struct {
	URL      string
	Title    string
	Server   string
	IPs      string
	CDN      string
	WAF      string
	Status   int
	Length   int
	Tech     []string
	AuthType string
	AuthURL  string
}

// Filter maps query flags to SQL conditions.
type Filter struct {
	Names    []string // substring match, OR'ed
	Tech     []string // per-item match, OR'ed
	WAF      string   // "", "yes", "no"
	WAFName  string
	Alive    string // "", "yes", "no"
	Status   []int
	New      bool
	Depth    int // -1 = any
	Root     string
	AuthType string // "", "register", "login_only", "landing"
	Target   string // target domain
}

// RootInfo represents summary information of a scanned root domain.
type RootInfo struct {
	Root        string  `json:"root"`
	Last        string  `json:"last"`
	Started     string  `json:"started,omitempty"`
	Finished    string  `json:"finished,omitempty"`
	Duration    string  `json:"duration,omitempty"`
	DurationSec float64 `json:"duration_sec,omitempty"`
	Scans       int     `json:"scans"`
}

// ReportData represents data passed to HTML template rendering.
type ReportData struct {
	Generated string     `json:"generated"`
	Roots     []RootInfo `json:"roots"`
	Hosts     []Host     `json:"hosts"`
}

// FormatDuration formats a time.Duration into a human-friendly string (e.g. 1h 2m 3s, 1m 5s, 5s, or 0.4s).
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	d = d.Round(time.Second)
	h := d / time.Hour
	m := (d % time.Hour) / time.Minute
	s := (d % time.Minute) / time.Second
	switch {
	case h > 0:
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	case m > 0:
		return fmt.Sprintf("%dm %ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
