package response

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestPortalTargetHrefValidation(t *testing.T) {
	lan := models.GatewayPortalConfig{NavigationMode: "lan"}
	for _, target := range []string{
		"http://192.168.1.10:8080/base?tab=1&view=all",
		"https://[fd00::10]:9443/a%20b?tab=1#details",
		"http://nas.internal:5000/app/",
	} {
		if got := gatewayPortalTargetHref(target, lan); got != target {
			t.Errorf("%s became %s", target, got)
		}
		if got := gatewayPortalTargetHref(target, models.GatewayPortalConfig{}); got != "" {
			t.Errorf("internet navigation leaked target href: %s", got)
		}
	}
	for _, target := range []string{
		"", "http://localhost:8080", "http://LOCALHOST.:8080", "http://app.localhost/",
		"http://127.0.0.1:8080", "http://127.5.6.7", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
		"http://127.1", "http://2130706433", "http://0x7f000001", "http://0177.0.0.1",
		"http://0.0.0.0/", "http://[::]/", "http://[fe80::1%25eth0]/",
		"javascript:alert(1)", "ws://192.168.1.2:80", "//192.168.1.2/", "/app",
		"http://user:secret@192.168.1.2/", "http://192.168.1.2:65536/",
		"http://192.168.1.2:0/", "http://192.168.1.2:bad/", "http://192.168.1.2/a b",
		"http://192.168.1.2\\@127.0.0.1", "http:///app",
		"http://[192.168.1.2]", "http://9999999999999999999999999999999",
		"http://fd00::1:8080/base", "http://2001:db8::1:8080/base",
		"http://[nas.internal]:5000/app/",
	} {
		if got := gatewayPortalTargetHref(target, lan); got != "" {
			t.Errorf("invalid or loopback target %q produced %q", target, got)
		}
	}
}

func TestPortalTargetHrefAcceptsBrowserHostnames(t *testing.T) {
	portal := models.GatewayPortalConfig{NavigationMode: "lan"}
	for target, want := range map[string]string{
		"http://bücher.internal:5000/a%20b?tab=1": "http://xn--bcher-kva.internal:5000/a%20b?tab=1",
		"http://nas_home.internal:5000/app/":      "http://nas_home.internal:5000/app/",
		"http://ｌｏｃａｌｈｏｓｔ:5000/app/":              "",
		"http://１２７.０.０.１:5000/app/":              "",
	} {
		if got := gatewayPortalTargetHref(target, portal); got != want {
			t.Errorf("%q produced %q, want %q", target, got, want)
		}
	}
}

func TestPortalPayloadAndSelectShareNavigation(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		for _, mode := range []string{"internet", "lan"} {
			for _, grouped := range []bool{false, true} {
				portal := models.GatewayPortalConfig{Version: version, NavigationMode: mode}
				hosts := []models.HostRule{
					{Host: "app.example.com", Target: "http://192.168.1.10:8080/base?tab=1"},
					{Host: "local.example.com", Target: "http://127.0.0.1:3000"},
				}
				if grouped {
					hosts[0].GroupID, hosts[0].GroupName = "apps", "Apps"
				}
				rules := []models.Rule{
					{Path: "/app", Target: "http://192.168.1.11:8081/base?tab=2"},
					{Path: "/local", Target: "http://localhost:3000"},
				}
				var payload struct {
					Data struct {
						Rules []struct{ Path, Href string } `json:"rules"`
						Hosts []struct{ Host, Href string } `json:"host_rules"`
					} `json:"data"`
				}
				body := GenerateToolbarDataWithPrefilteredHostsForLocale("en", rules, hosts, "/", "", "", portal)
				if err := json.Unmarshal([]byte(body), &payload); err != nil {
					t.Fatal(err)
				}
				wantHost, wantPath := "", ""
				if mode == "lan" {
					wantHost, wantPath = hosts[0].Target, rules[0].Target
				}
				if payload.Data.Hosts[0].Href != wantHost || payload.Data.Rules[0].Href != wantPath ||
					payload.Data.Hosts[1].Href != "" || payload.Data.Rules[1].Href != "" {
					t.Fatalf("%s/%s/grouped=%v: unexpected payload %s", version, mode, grouped, body)
				}
				for _, withHosts := range []bool{false, true} {
					selectedHosts := hosts
					if !withHosts {
						selectedHosts = nil
					}
					rec := httptest.NewRecorder()
					SelectPage(rec, httptest.NewRequest("GET", "https://gateway.example.com/__select__", nil), rules, selectedHosts, portal)
					want := `href="` + rules[0].Target + `"`
					if withHosts {
						want = `href="` + hosts[0].Target + `"`
					}
					if got := strings.Contains(rec.Body.String(), want); got != (mode == "lan") {
						t.Fatalf("%s/%s/grouped=%v/hosts=%v: wrong select href", version, mode, grouped, withHosts)
					}
					if !withHosts && !strings.Contains(rec.Body.String(), `href="/local/"`) {
						t.Fatal("loopback path must fall back to the gateway path")
					}
				}
			}
		}
	}
}
