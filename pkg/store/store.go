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
  server TEXT DEFAULT '', tech TEXT DEFAULT '', ips TEXT DEFAULT '', cdn TEXT DEFAULT '',
  waf TEXT DEFAULT '', length INT DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_scans_root ON scans(root);
CREATE INDEX IF NOT EXISTS idx_hosts_root_depth ON hosts(root, depth);
CREATE INDEX IF NOT EXISTS idx_hosts_alive ON hosts(alive);
CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);`

const hostCols = `host, root, depth, sources, first_seen, last_seen,
  first_scan = (SELECT max(id) FROM scans s WHERE s.root = hosts.root),
  alive, url, status, title, server, tech, ips, cdn, waf, length`

// Store handles persistence of scan results and hosts in SQLite.
type Store struct {
	db        *sql.DB
	upsertSt  *sql.Stmt
	probeSt   *sql.Stmt
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
			db.Close()
			return nil, fmt.Errorf("create schema: %w", err)
		}
		// Pre-compile hot-path statements to avoid SQL re-parsing on every host/probe callback.
		st.upsertSt, err = db.Prepare(`
INSERT INTO hosts(host, root, depth, sources, first_seen, last_seen, first_scan, last_scan)
VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(host) DO UPDATE SET
  last_seen=excluded.last_seen, last_scan=excluded.last_scan,
  depth=min(hosts.depth, excluded.depth), sources=excluded.sources`)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("prepare upsert: %w", err)
		}
		st.probeSt, err = db.Prepare(`
UPDATE hosts SET alive=1, url=?, status=?, title=?, server=?, tech=?, ips=?, cdn=?, waf=?, length=?
WHERE host=?`)
		if err != nil {
			st.Close()
			return nil, fmt.Errorf("prepare probe: %w", err)
		}
	}
	return st, nil
}

// Close closes the underlying SQLite database and prepared statements.
func (s *Store) Close() error {
	if s.upsertSt != nil {
		_ = s.upsertSt.Close()
	}
	if s.probeSt != nil {
		_ = s.probeSt.Close()
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// DB returns the underlying sql.DB.
func (s *Store) DB() *sql.DB {
	return s.db
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

// SaveProbe updates probe results for a host.
func (s *Store) SaveProbe(host string, p types.Probe) error {
	_, err := s.probeSt.Exec(p.URL, p.Status, p.Title, p.Server, packTech(p.Tech), p.IPs, p.CDN, p.WAF, p.Length, host)
	return err
}

// ResetProbe clears last scan's probe data so hosts that went down show as dead.
func (s *Store) ResetProbe(root string) error {
	_, err := s.db.Exec(`UPDATE hosts SET alive=0, url='', status=0, title='', server='', tech='', ips='', cdn='', waf='', length=0 WHERE root=?`, root)
	return err
}

// QueryHosts fetches hosts matching the given filter.
func (s *Store) QueryHosts(f types.Filter) ([]types.Host, error) {
	w, args := buildWhere(f)
	rows, err := s.db.Query("SELECT "+hostCols+" FROM hosts"+w+" ORDER BY root, depth, host", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Host
	for rows.Next() {
		var h types.Host
		var tech string
		if err := rows.Scan(&h.Host, &h.Root, &h.Depth, &h.Sources, &h.FirstSeen, &h.LastSeen, &h.New,
			&h.Alive, &h.URL, &h.Status, &h.Title, &h.Server, &tech, &h.IPs, &h.CDN, &h.WAF, &h.Length); err != nil {
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
	rows, err := s.db.Query(`SELECT root, coalesce(max(finished), max(started)), count(*) FROM scans GROUP BY root ORDER BY root`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roots := []types.RootInfo{}
	for rows.Next() {
		var r types.RootInfo
		if err := rows.Scan(&r.Root, &r.Last, &r.Scans); err != nil {
			return nil, err
		}
		roots = append(roots, r)
	}
	return roots, rows.Err()
}

func buildWhere(f types.Filter) (string, []any) {
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
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
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
