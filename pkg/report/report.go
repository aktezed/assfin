package report

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"io"
	"os"
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

// RenderReport queries data from store and renders the HTML report to w.
func RenderReport(s *store.Store, w io.Writer) error {
	hosts, err := s.QueryHosts(types.Filter{Depth: -1})
	if err != nil {
		return err
	}
	if hosts == nil {
		hosts = []types.Host{}
	}
	roots, err := s.GetScansSummary()
	if err != nil {
		return err
	}

	data := types.ReportData{
		Generated: time.Now().UTC().Format(time.RFC3339),
		Roots:     roots,
		Hosts:     hosts,
	}

	rawJSON, err := json.Marshal(data)
	if err != nil {
		return err
	}

	payload := templatePayload{
		DataJSON: template.JS(rawJSON),
	}

	return reportTmpl.Execute(w, payload)
}

// WriteReport queries data from store and writes the HTML report to out.
func WriteReport(s *store.Store, out string) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	return RenderReport(s, f)
}
