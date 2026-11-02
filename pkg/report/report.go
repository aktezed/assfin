package report

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aktezed/assfin/pkg/store"
	"github.com/aktezed/assfin/pkg/types"
)

//go:embed report.html
var reportHTML string

var reportTmpl = template.Must(template.New("report").Parse(reportHTML))

type templatePayload struct {
	DataJSON template.JS
}

// RenderReport queries all data from store and renders the HTML report to w.
func RenderReport(s *store.Store, w io.Writer) error {
	return RenderScopedReport(s, "", w)
}

// RenderScopedReport queries data from store (optionally scoped to root) and renders the HTML report to w.
func RenderScopedReport(s *store.Store, root string, w io.Writer) error {
	root = strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(root)), "."), "*.")

	hosts, err := s.QueryHosts(types.Filter{Root: root, Depth: -1})
	if err != nil {
		return err
	}
	if hosts == nil {
		hosts = []types.Host{}
	}

	allRoots, err := s.GetScansSummary()
	if err != nil {
		return err
	}
	roots := allRoots
	if root != "" {
		roots = make([]types.RootInfo, 0, 1)
		for _, r := range allRoots {
			if r.Root == root {
				roots = append(roots, r)
			}
		}
	}

	refs, err := s.QueryHostRefs(root)
	if err != nil {
		return err
	}

	data := types.ReportData{
		Generated: time.Now().UTC().Format(time.RFC3339),
		Roots:     roots,
		Hosts:     hosts,
		Refs:      refs,
	}

	rawJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return reportTmpl.Execute(w, templatePayload{
		DataJSON: template.JS(rawJSON),
	})
}

// WriteReport queries all data from store and writes the HTML report to out.
func WriteReport(s *store.Store, out string) error {
	return WriteScopedReport(s, "", out)
}

// WriteScopedReport queries data from store (optionally scoped to root) and writes the HTML report to out.
func WriteScopedReport(s *store.Store, root, out string) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	return RenderScopedReport(s, root, f)
}
