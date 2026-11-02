package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aktezed/assfin/pkg/types"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY, root TEXT, started TEXT, finished TEXT, opts TEXT);
CREATE TABLE IF NOT EXISTS hosts (
  host TEXT PRIMARY KEY, root TEXT, depth INT, sources TEXT,
  first_seen TEXT, last_seen TEXT, first_scan INT, last_scan INT,
  alive INT DEFAULT 0, url TEXT DEFAULT '', status INT DEFAULT 0, title TEXT DEFAULT '',
  server TEXT DEFAULT '', tech TEXT DEFAULT '', ips TEXT DEFAULT '', cname TEXT DEFAULT '', cdn TEXT DEFAULT '',
  waf TEXT DEFAULT '', length INT DEFAULT 0, auth_type TEXT DEFAULT '', auth_url TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS host_refs (
  host TEXT NOT NULL, referrer TEXT NOT NULL, source TEXT NOT NULL,
  first_seen TEXT, last_seen TEXT,
  PRIMARY KEY (host, referrer));
CREATE INDEX IF NOT EXISTS idx_scans_root ON scans(root);
CREATE INDEX IF NOT EXISTS idx_hosts_root_depth ON hosts(root, depth);
CREATE INDEX IF NOT EXISTS idx_hosts_alive ON hosts(alive);
CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
CREATE INDEX IF NOT EXISTS idx_host_refs_referrer ON host_refs(referrer);`

const hostCols = `host, root, depth, sources, first_seen, last_seen,
  first_scan = (SELECT max(id) FROM scans s WHERE s.root = hosts.root),
  alive, url, status, title, server, tech, ips, coalesce(cname, ''), cdn, waf, length, auth_type, auth_url`

const hostColsLegacy = `host, root, depth, sources, first_seen, last_seen,
  first_scan = (SELECT max(id) FROM scans s WHERE s.root = hosts.root),
  alive, url, status, title, server, tech, ips, '' AS cname, cdn, waf, length, auth_type, auth_url`

// Store handles persistence of scan results and hosts in SQLite.
type Store struct {
	db              *sql.DB
	upsertSt        *sql.Stmt
	contentUpsertSt *sql.Stmt
	refSt           *sql.Stmt
	dnsSt           *sql.Stmt
	probeSt         *sql.Stmt
	hasCNAME        bool
}

// New opens or creates a SQLite database at the specified path.
func New(path string, readOnly bool) (*Store, error) {
	// WAL + synchronous=NORMAL + in-memory temp store yields ~10x faster writes while remaining crash-safe.
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=temp_store(MEMORY)&_pragma=cache_size(-20000)"
	if readOnly {
		dsn = "file:" + path + "?mode=ro&_pragma=busy_timeout(5000)&_pragma=temp_store(MEMORY)&_pragma=cache_size(-20000)"
	} else if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // single writer; callbacks serialize here
	st := &Store{db: db}
	if !readOnly {
		if _, err := db.Exec(schema); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("create schema: %w", err)
		}
		// Migrate older databases if columns are missing
		_, _ = db.Exec(`ALTER TABLE hosts ADD COLUMN auth_type TEXT DEFAULT ''`)
		_, _ = db.Exec(`ALTER TABLE hosts ADD COLUMN auth_url TEXT DEFAULT ''`)
		_, _ = db.Exec(`ALTER TABLE hosts ADD COLUMN cname TEXT DEFAULT ''`)
		st.hasCNAME = true

		// Pre-compile hot-path statements to avoid SQL re-parsing on every host/probe callback.
		st.upsertSt, err = db.Prepare(`
INSERT INTO hosts(host, root, depth, sources, first_seen, last_seen, first_scan, last_scan)
VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(host) DO UPDATE SET
  last_seen=excluded.last_seen, last_scan=excluded.last_scan,
  depth=min(hosts.depth, excluded.depth), sources=excluded.sources`)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("prepare upsert: %w", err)
		}
		st.contentUpsertSt, err = db.Prepare(`
INSERT INTO hosts(host, root, depth, sources, first_seen, last_seen, first_scan, last_scan)
VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(host) DO UPDATE SET
  last_seen=excluded.last_seen, last_scan=excluded.last_scan,
  depth=min(hosts.depth, excluded.depth),
  sources=CASE WHEN hosts.sources = '' THEN excluded.sources ELSE hosts.sources END`)
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("prepare content upsert: %w", err)
		}
		st.refSt, err = db.Prepare(`
INSERT INTO host_refs(host, referrer, source, first_seen, last_seen)
VALUES(?,?,?,?,?)
ON CONFLICT(host, referrer) DO UPDATE SET
  source=excluded.source, last_seen=excluded.last_seen`)
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("prepare host_refs: %w", err)
		}
		st.dnsSt, err = db.Prepare(`
UPDATE hosts SET ips=?, cname=?, cdn=?, waf=CASE WHEN ? <> '' THEN ? ELSE waf END
WHERE host=?`)
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("prepare dns: %w", err)
		}
		st.probeSt, err = db.Prepare(`
UPDATE hosts SET alive=1, url=?, status=?, title=?, server=?, tech=?,
  ips=CASE WHEN ? <> '' THEN ? ELSE ips END,
  cdn=CASE WHEN ? <> '' THEN ? ELSE cdn END,
  waf=CASE WHEN ? <> '' THEN ? ELSE waf END,
  length=?, auth_type=?, auth_url=?
WHERE host=?`)
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("prepare probe: %w", err)
		}
	} else {
		st.hasCNAME = tableHasColumn(db, "hosts", "cname")
	}
	return st, nil
}

func tableHasColumn(db *sql.DB, table, col string) bool {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid       int
			name      string
			colType   string
			notNull   int
			dfltValue any
			pk        int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err == nil && strings.EqualFold(name, col) {
			return true
		}
	}
	return false
}

// Close closes the underlying SQLite database and prepared statements.
func (s *Store) Close() error {
	if s.upsertSt != nil {
		_ = s.upsertSt.Close()
	}
	if s.contentUpsertSt != nil {
		_ = s.contentUpsertSt.Close()
	}
	if s.refSt != nil {
		_ = s.refSt.Close()
	}
	if s.dnsSt != nil {
		_ = s.dnsSt.Close()
	}
	if s.probeSt != nil {
		_ = s.probeSt.Close()
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// StartScan records the start of a scan run.
func (s *Store) StartScan(root, opts string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO scans(root, started, opts) VALUES(?,?,?)`, root, now(), opts)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishScan marks a scan run as completed.
func (s *Store) FinishScan(id int64) error {
	_, err := s.db.Exec(`UPDATE scans SET finished=? WHERE id=?`, now(), id)
	return err
}

// UpsertHost records a discovered host, keeping its first-seen info on re-runs.
func (s *Store) UpsertHost(scan int64, root, host string, depth int, sources []string) error {
	t := now()
	_, err := s.upsertSt.Exec(host, root, depth, strings.Join(sources, ","), t, t, scan, scan)
	return err
}

// UpsertContentHost records a content-derived host without overwriting non-empty passive sources.
func (s *Store) UpsertContentHost(scan int64, root, host string, depth int, referrer string) error {
	t := now()
	src := ""
	if referrer != "" {
		src = "content:" + referrer
	}
	_, err := s.contentUpsertSt.Exec(host, root, depth, src, t, t, scan, scan)
	return err
}

// SaveHostRef records or updates a cross-host reference extracted from HTTP content.
func (s *Store) SaveHostRef(host, referrer, source string) error {
	t := now()
	_, err := s.refSt.Exec(host, referrer, source, t, t)
	return err
}

// QueryHostRefs returns content-derived host references, optionally scoped to a root domain.
func (s *Store) QueryHostRefs(root string) ([]types.HostRef, error) {
	query := "SELECT r.host, r.referrer, r.source, coalesce(r.first_seen, ''), coalesce(r.last_seen, '') FROM host_refs r"
	var args []any
	if root != "" {
		query += " JOIN hosts h ON h.host = r.host WHERE h.root = ?"
		args = append(args, root)
	}
	query += " ORDER BY r.host, r.referrer"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		// Legacy databases opened in read-only mode predate the host_refs table.
		if strings.Contains(err.Error(), "no such table: host_refs") {
			return []types.HostRef{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	out := []types.HostRef{}
	for rows.Next() {
		var ref types.HostRef
		if err := rows.Scan(&ref.Host, &ref.Referrer, &ref.Source, &ref.FirstSeen, &ref.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

// SaveDNS updates DNS records (IPs, CNAME chain, CDN, and IP-range WAF) for a host.
func (s *Store) SaveDNS(host string, d types.DNSResult) error {
	_, err := s.dnsSt.Exec(d.IPs, d.CNAME, d.CDN, d.WAF, d.WAF, host)
	return err
}

// SaveProbe updates probe results for a host while preserving DNS fields when httpx leaves them blank.
func (s *Store) SaveProbe(host string, p types.Probe) error {
	_, err := s.probeSt.Exec(
		p.URL, p.Status, p.Title, p.Server, packTech(p.Tech),
		p.IPs, p.IPs, p.CDN, p.CDN, p.WAF, p.WAF,
		p.Length, p.AuthType, p.AuthURL, host,
	)
	return err
}

// UpdateAuth updates the asset role classification and auth URL for a host.
func (s *Store) UpdateAuth(host, authType, authURL string) error {
	_, err := s.db.Exec(`UPDATE hosts SET auth_type=?, auth_url=? WHERE host=?`, authType, authURL, host)
	return err
}

// ResetDNS clears previous DNS resolution columns for a root domain before a DNS-only refresh.
func (s *Store) ResetDNS(root string) error {
	_, err := s.db.Exec(`UPDATE hosts SET ips='', cname='', cdn='' WHERE root=?`, root)
	return err
}

// ResetProbe clears last scan's DNS and probe data so hosts that went down show as dead.
func (s *Store) ResetProbe(root string) error {
	_, err := s.db.Exec(`UPDATE hosts SET alive=0, url='', status=0, title='', server='', tech='', ips='', cname='', cdn='', waf='', length=0, auth_type='', auth_url='' WHERE root=?`, root)
	return err
}

// DeleteHosts removes wildcard-polluted subdomains (never deleting the root apex) and any associated host_refs.
func (s *Store) DeleteHosts(root string, hosts []string) error {
	filtered := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h != "" && h != root {
			filtered = append(filtered, h)
		}
	}
	if len(filtered) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	const batchSize = 400
	for start := 0; start < len(filtered); start += batchSize {
		chunk := filtered[start:min(start+batchSize, len(filtered))]
		n := len(chunk)
		ph := strings.TrimSuffix(strings.Repeat("?,", n), ",")

		// Box each hostname once into a single backing slice shared across both DELETE statements.
		args := make([]any, 1+n*2)
		args[0] = root
		for i, h := range chunk {
			args[1+i] = h
		}
		copy(args[1+n:], args[1:1+n])

		if _, err := tx.Exec("DELETE FROM hosts WHERE root = ? AND host IN ("+ph+")", args[:1+n]...); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM host_refs WHERE host IN ("+ph+") OR referrer IN ("+ph+")", args[1:]...); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// QueryHosts fetches hosts matching the given filter.
func (s *Store) QueryHosts(f types.Filter) ([]types.Host, error) {
	w, args := buildWhere(f, s.hasCNAME)
	cols := hostCols
	if !s.hasCNAME {
		cols = hostColsLegacy
	}
	rows, err := s.db.Query("SELECT "+cols+" FROM hosts"+w+" ORDER BY root, depth, host", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Host
	for rows.Next() {
		var h types.Host
		var tech string
		if err := rows.Scan(&h.Host, &h.Root, &h.Depth, &h.Sources, &h.FirstSeen, &h.LastSeen, &h.New,
			&h.Alive, &h.URL, &h.Status, &h.Title, &h.Server, &tech, &h.IPs, &h.CNAME, &h.CDN, &h.WAF, &h.Length,
			&h.AuthType, &h.AuthURL); err != nil {
			return nil, err
		}
		h.Tech = unpackTech(tech)
		out = append(out, h)
	}
	return out, rows.Err()
}

// RawQuery runs raw SQL against the database.
func (s *Store) RawQuery(q string) ([]string, [][]string, error) {
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, nil, err
	}
	var out [][]string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, nil, err
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			switch x := v.(type) {
			case nil:
			case []byte:
				row[i] = string(x)
			case int64:
				row[i] = strconv.FormatInt(x, 10)
			default:
				row[i] = fmt.Sprint(x)
			}
		}
		out = append(out, row)
	}
	return cols, out, rows.Err()
}

// GetScansSummary returns a summary of scans grouped by root domain.
func (s *Store) GetScansSummary() ([]types.RootInfo, error) {
	query := `
SELECT s.root,
       coalesce(s.finished, s.started, '') AS last,
       (SELECT count(*) FROM scans WHERE root = s.root) AS scan_count,
       coalesce(s.started, ''),
       coalesce(s.finished, '')
FROM scans s
WHERE s.id IN (SELECT max(id) FROM scans GROUP BY root)
ORDER BY s.root`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roots := []types.RootInfo{}
	for rows.Next() {
		var r types.RootInfo
		if err := rows.Scan(&r.Root, &r.Last, &r.Scans, &r.Started, &r.Finished); err != nil {
			return nil, err
		}
		if r.Started != "" && r.Finished != "" {
			tStart, err1 := time.Parse(time.RFC3339, r.Started)
			tFinish, err2 := time.Parse(time.RFC3339, r.Finished)
			if err1 == nil && err2 == nil && !tFinish.Before(tStart) {
				dur := tFinish.Sub(tStart)
				r.Duration = types.FormatDuration(dur)
				r.DurationSec = dur.Seconds()
			}
		}
		roots = append(roots, r)
	}
	return roots, rows.Err()
}

func buildWhere(f types.Filter, hasCNAME bool) (string, []any) {
	var conds []string
	var args []any
	or := func(col, pattern string, vals []string) {
		if len(vals) == 0 {
			return
		}
		parts := make([]string, len(vals))
		for i, v := range vals {
			parts[i] = col + ` LIKE ? ESCAPE '\'`
			args = append(args, fmt.Sprintf(pattern, likeEscape(v)))
		}
		conds = append(conds, "("+strings.Join(parts, " OR ")+")")
	}
	or("host", "%%%s%%", f.Names)
	or("tech", "%%,%s%%", f.Tech)
	switch f.WAF {
	case "yes":
		conds = append(conds, "waf <> ''")
	case "no":
		conds = append(conds, "waf = ''")
	}
	if f.WAFName != "" {
		conds = append(conds, `waf LIKE ? ESCAPE '\'`)
		args = append(args, "%"+likeEscape(f.WAFName)+"%")
	}
	switch f.Alive {
	case "yes":
		conds = append(conds, "alive = 1")
	case "no":
		conds = append(conds, "alive = 0")
	}
	switch f.Resolved {
	case "yes":
		conds = append(conds, "ips <> ''")
	case "no":
		conds = append(conds, "ips = ''")
	}
	if f.HasCNAME || len(f.CNAMETarget) > 0 || f.Dangling {
		if !hasCNAME {
			conds = append(conds, "1 = 0")
		} else {
			if f.HasCNAME {
				conds = append(conds, "cname <> ''")
			}
			or("cname", "%%%s%%", f.CNAMETarget)
			if f.Dangling {
				conds = append(conds, "cname <> '' AND ips = ''")
			}
		}
	}
	if len(f.Status) > 0 {
		conds = append(conds, "status IN ("+strings.TrimSuffix(strings.Repeat("?,", len(f.Status)), ",")+")")
		for _, s := range f.Status {
			args = append(args, s)
		}
	}
	if f.New {
		conds = append(conds, "first_scan = (SELECT max(id) FROM scans WHERE root = hosts.root)")
	}
	if f.Depth >= 0 {
		conds = append(conds, "depth = ?")
		args = append(args, f.Depth)
	}
	if f.Root != "" {
		conds = append(conds, "root = ?")
		args = append(args, f.Root)
	}
	if f.AuthType != "" {
		conds = append(conds, "auth_type = ?")
		args = append(args, f.AuthType)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

var sqlLikeReplacer = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func likeEscape(s string) string {
	return sqlLikeReplacer.Replace(s)
}

func packTech(t []string) string {
	if len(t) == 0 {
		return ""
	}
	return "," + strings.Join(t, ",") + ","
}

func unpackTech(s string) []string {
	s = strings.Trim(s, ",")
	if s == "" {
		return []string{}
	}
	return strings.Split(s, ",")
}
