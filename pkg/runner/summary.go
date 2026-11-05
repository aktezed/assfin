package runner

import (
	"fmt"
	"io"
	"strings"

	"github.com/aktezed/assfin/pkg/types"
)

// PrintTargetSummary writes a structured, headless terminal dossier for a target domain.
func PrintTargetSummary(w io.Writer, root string, hosts []types.Host, sourceStats ...types.SourceStat) {
	if len(hosts) == 0 && len(sourceStats) == 0 {
		fmt.Fprintf(w, "No assets discovered for target: %s\n", root)
		return
	}

	var (
		alive         int
		resolvedCount int
		wafCount      int
		fresh         int
		regHosts      []types.Host
		loginHosts    []types.Host
		landHosts     []types.Host
		unreach       []types.Host
		contentHosts  []types.Host
		danglingHosts []types.Host
	)

	for _, h := range hosts {
		if h.Alive {
			alive++
			switch h.AuthType {
			case "register":
				regHosts = append(regHosts, h)
			case "login_only":
				loginHosts = append(loginHosts, h)
			case "landing":
				landHosts = append(landHosts, h)
			default:
				landHosts = append(landHosts, h)
			}
		} else {
			unreach = append(unreach, h)
		}
		if h.IPs != "" {
			resolvedCount++
		}
		if h.CNAME != "" && h.IPs == "" {
			danglingHosts = append(danglingHosts, h)
		}
		if h.WAF != "" {
			wafCount++
		}
		if h.New {
			fresh++
		}
		if strings.HasPrefix(h.Sources, "content:") {
			contentHosts = append(contentHosts, h)
		}
	}

	div := strings.Repeat("═", 78)
	subDiv := strings.Repeat("─", 78)

	fmt.Fprintln(w, div)
	fmt.Fprintf(w, "  TARGET DOSSIER : %s\n", strings.ToUpper(root))
	fmt.Fprintln(w, div)
	fmt.Fprintf(w, "  Total Discovered Subdomains : %-6d  Alive Web Endpoints : %d\n", len(hosts), alive)
	fmt.Fprintf(w, "  DNS Resolved Hosts          : %-6d  Dangling CNAMEs     : %d\n", resolvedCount, len(danglingHosts))
	fmt.Fprintf(w, "  Behind WAF Protection       : %-6d  New In Latest Scan  : %d\n", wafCount, fresh)
	fmt.Fprintf(w, "  Discovered via Content      : %-6d  (Extended beyond passive CT)\n", len(contentHosts))
	fmt.Fprintln(w, subDiv)
	fmt.Fprintln(w, "  ASSET ROLE CLASSIFICATION:")
	fmt.Fprintf(w, "    [REGISTERABLE] : %-4d (Open registration or sign-up endpoint detected)\n", len(regHosts))
	fmt.Fprintf(w, "    [LOGIN-ONLY]   : %-4d (Authentication/portal present, registration closed)\n", len(loginHosts))
	fmt.Fprintf(w, "    [LANDING PAGE] : %-4d (Public marketing / presentation site)\n", len(landHosts))
	fmt.Fprintf(w, "    [UNREACHABLE]  : %-4d (Non-responsive or dead hosts)\n", len(unreach))

	if len(regHosts) > 0 {
		fmt.Fprintln(w, subDiv)
		fmt.Fprintln(w, "  REGISTERABLE ASSETS (Actionable Signup Targets):")
		for _, h := range regHosts {
			targetURL := h.AuthURL
			if targetURL == "" {
				targetURL = h.URL
			}
			wafLabel := ""
			if h.WAF != "" {
				wafLabel = fmt.Sprintf(" [%s]", h.WAF)
			}
			fmt.Fprintf(w, "    • %-32s -> %s%s\n", h.Host, targetURL, wafLabel)
		}
	}

	if len(loginHosts) > 0 {
		fmt.Fprintln(w, subDiv)
		fmt.Fprintln(w, "  LOGIN-ONLY ASSETS (Authentication Portals):")
		for _, h := range loginHosts {
			targetURL := h.AuthURL
			if targetURL == "" {
				targetURL = h.URL
			}
			wafLabel := ""
			if h.WAF != "" {
				wafLabel = fmt.Sprintf(" [%s]", h.WAF)
			}
			fmt.Fprintf(w, "    • %-32s -> %s%s\n", h.Host, targetURL, wafLabel)
		}
	}

	if len(danglingHosts) > 0 {
		fmt.Fprintln(w, subDiv)
		fmt.Fprintln(w, "  DANGLING CNAME RECORDS (Unresolved CNAME Targets):")
		for _, h := range danglingHosts {
			fmt.Fprintf(w, "    • %-32s -> %s [unresolved]\n", h.Host, h.CNAME)
		}
	}

	if len(contentHosts) > 0 {
		fmt.Fprintln(w, subDiv)
		fmt.Fprintln(w, "  DISCOVERED VIA CONTENT (Wildcard / Non-CT Assets):")
		for _, h := range contentHosts {
			referrer := strings.TrimPrefix(h.Sources, "content:")
			statusLabel := "dead"
			if h.Alive {
				statusLabel = fmt.Sprintf("%d", h.Status)
			}
			wafLabel := ""
			if h.WAF != "" {
				wafLabel = fmt.Sprintf(" [%s]", h.WAF)
			}
			fmt.Fprintf(w, "    • %-32s <- via %s [%s]%s\n", h.Host, referrer, statusLabel, wafLabel)
		}
	}

	if len(sourceStats) > 0 {
		fmt.Fprintln(w, subDiv)
		fmt.Fprintln(w, "  PASSIVE SOURCE SUMMARY:")
		for _, s := range sourceStats {
			fmt.Fprintf(w, "    • %s: %d returned, %d unresolvable, %d malformed\n",
				s.Source, s.Returned, s.Unresolvable, s.Malformed)
		}
	}

	fmt.Fprintln(w, div)
}
