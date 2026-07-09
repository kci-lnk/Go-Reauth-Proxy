package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestDiagnosticsServerRequiresLoopbackAndToken(t *testing.T) {
	if _, _, err := startDiagnosticsServer("0.0.0.0:0", "token"); err == nil {
		t.Fatal("startDiagnosticsServer accepted a non-loopback address")
	}
	if _, _, err := startDiagnosticsServer("127.0.0.1:0", ""); err == nil {
		t.Fatal("startDiagnosticsServer accepted an empty token")
	}

	stop, addr, err := startDiagnosticsServer("127.0.0.1:0", "secret")
	if err != nil {
		t.Fatalf("startDiagnosticsServer() returned error: %v", err)
	}
	defer stop()

	response, err := http.Get("http://" + addr + "/debug/metrics")
	if err != nil {
		t.Fatalf("unauthorized GET failed: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", response.StatusCode)
	}

	request, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/debug/metrics", nil)
	request.Header.Set("x-fn-knock-internal-rpc-token", "secret")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("authorized GET failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authorized status = %d", response.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode metrics: %v", err)
	}
	if _, ok := body["runtime"]; !ok {
		t.Fatalf("metrics body missing runtime: %#v", body)
	}
}
