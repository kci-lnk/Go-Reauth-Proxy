package proxy

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestOnlineDeviceClassification(t *testing.T) {
	for _, tc := range []struct{ ua, want string }{
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "macos"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)", "iphone"},
		{"Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X)", "ipad"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Mobile/15E148", "ipad"},
		{"Mozilla/5.0 (Linux; Android 15; Pixel 9)", "android"},
		{"Mozilla/5.0 (X11; Linux x86_64)", "linux"},
		{"Mozilla/5.0 (X11; CrOS x86_64 16093.68.0)", "chromeos"},
		{"Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0 Mobile Safari/537.36 Edge/15.15063", "windows"},
		{"Mozilla/5.0 (Windows Phone 8.1; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 630) like Gecko (like iPhone OS 7_0_3 Mac OS X) AppleWebKit/537 (KHTML, like Gecko) Mobile Safari/537", "windows"},
		{"Mozilla/5.0 (iPod touch; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148", "unknown"},
		{"", "unknown"}, {"curl/8.0", "unknown"},
	} {
		t.Run(tc.want+tc.ua, func(t *testing.T) {
			if got := onlineDeviceType(tc.ua); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestOnlineDevicesAggregateLatestIdentityActivity(t *testing.T) {
	h := &Handler{}
	now := time.Now().UTC()
	request := func(identity, ua, ip string, when time.Time) {
		r := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
		r.AddCookie(&http.Cookie{Name: "app-session", Value: identity})
		r.Header.Set("User-Agent", ua)
		h.markLoggedInActive(r, ip, when)
	}
	ip := "192.0.2.1"
	request("mac", "Macintosh", ip, now)
	request("win1", "Windows NT 10.0", ip, now)
	request("win2", "Windows NT 10.0", ip, now)
	request("phone", "iPhone like Mac OS X", ip, now)
	request("win1", "Windows NT 10.0", ip, now.Add(time.Second))
	got := h.GetOnlineIPs(now)
	want := []OnlineDeviceStats{{Type: "iphone", Count: 1}, {Type: "macos", Count: 1}, {Type: "windows", Count: 2}}
	if got.OnlineCount != 4 || len(got.Items) != 1 || !reflect.DeepEqual(got.Items[0].Devices, want) {
		t.Fatalf("unexpected aggregate: %+v", got)
	}
	request("win1", "Linux; Android", "2001:db8::1", now.Add(2*time.Second))
	request("win1", "Windows", ip, now) // stale request cannot restore IP or platform
	got = h.GetOnlineIPs(now)
	if got.Items[0].IP != "2001:db8::1" || !reflect.DeepEqual(got.Items[0].Devices, []OnlineDeviceStats{{Type: "android", Count: 1}}) {
		t.Fatalf("latest activity lost: %+v", got)
	}
	request("phone", "", ip, now.Add(3*time.Second))
	h.MarkLoggedInActiveByClientIP("192.0.2.2", now)
	got = h.GetOnlineIPs(now)
	var unknown int64
	for _, item := range got.Items {
		var sum int64
		for _, device := range item.Devices {
			sum += device.Count
			if device.Type == "unknown" {
				unknown += device.Count
			}
		}
		if sum != item.IdentityCount {
			t.Fatalf("device count differs from identities: %+v", item)
		}
	}
	if unknown != 2 {
		t.Fatalf("unknown count = %d", unknown)
	}
	if got := h.GetOnlineIPs(now.Add(loggedInActiveWindow + 4*time.Second)); len(got.Items) != 0 {
		t.Fatalf("not expired: %+v", got)
	}
}
