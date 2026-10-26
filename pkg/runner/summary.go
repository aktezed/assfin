package runner

import (
	"fmt"
	"io"
	"strings"

	"github.com/aktezed/assfin/pkg/types"
)

// PrintTargetSummary writes a structured, headless terminal dossier for a target domain.
func PrintTargetSummary(w io.Writer, root string, hosts []types.Host) {
	if len(hosts) == 0 {
		fmt.Fprintf(w, "No assets discovered for target: %s\n", root)
		return
	}

	var (
		alive       int
		wafCount    int
		fresh       int
		regHosts    []types.Host
		loginHosts  []types.Host
		landHosts   []types.Host
		unreach     []types.Host
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
		if h.WAF != "" {
			wafCount++
		}
		if h.New {
			fresh++
		}
	}

	div := strings.Repeat("═", 78)
	subDiv := strings.Repeat("─", 78)

	fmt.Fprintln(w, div)
	fmt.Fprintf(w, "  TARGET DOSSIER : %s\n", strings.ToUpper(root))
	fmt.Fprintln(w, div)
	fmt.Fprintf(w, "  Total Discovered Subdomains : %-6d  Alive Web Endpoints : %d\n", len(hosts), alive)
	fmt.Fprintf(w, "  Behind WAF Protection       : %-6d  New In Latest Scan  : %d\n", wafCount, fresh)
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

	fmt.Fprintln(w, div)
}
