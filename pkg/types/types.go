package types

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
}

// Probe is the subset of an httpx result stored per host.
type Probe struct {
	URL    string
	Title  string
	Server string
	IPs    string
	CDN    string
	WAF    string
	Status int
	Length int
	Tech   []string
}

// Filter maps query flags to SQL conditions.
type Filter struct {
	Names   []string // substring match, OR'ed
	Tech    []string // per-item match, OR'ed
	WAF     string   // "", "yes", "no"
	WAFName string
	Alive   string // "", "yes", "no"
	Status  []int
	New     bool
	Depth   int // -1 = any
	Root    string
}

// RootInfo represents summary information of a scanned root domain.
type RootInfo struct {
	Root  string `json:"root"`
	Last  string `json:"last"`
	Scans int    `json:"scans"`
}

// ReportData represents data passed to HTML template rendering.
type ReportData struct {
	Generated string     `json:"generated"`
	Roots     []RootInfo `json:"roots"`
	Hosts     []Host     `json:"hosts"`
}
