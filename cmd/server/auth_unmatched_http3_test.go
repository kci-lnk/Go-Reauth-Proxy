package main

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go-reauth-proxy/pkg/models"
)

func TestHTTP3AuthUnmatchedAbortsOnlyCurrentStream(t *testing.T) {
	_, h, addr := http3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.Header().Set("X-Fn-Knock-Auth-Route-Unmatched", "1")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	target, err := url.Parse(h.GetHostRules()[0].Target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(target.Port())
	if err != nil {
		t.Fatal(err)
	}
	auth := h.GetAuthConfig()
	auth.AuthHost = "app.example.test"
	auth.AuthPort = port
	if err := h.SetAuthConfig(auth); err != nil {
		t.Fatal(err)
	}
	if _, err := h.SetGatewayUnmatchedRouteConfig(models.GatewayUnmatchedRouteConfig{
		Behavior: models.GatewayUnmatchedRouteBehaviorResetConnection,
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{InsecureSkipVerify: true, ServerName: "app.example.test", NextProtos: []string{"h3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	transport := &http3.Transport{}
	defer transport.Close()
	client := &http.Client{Transport: transport.NewClientConn(conn), Timeout: 5 * time.Second}
	if resp, err := client.Get("https://app.example.test/missing"); err == nil {
		resp.Body.Close()
		t.Fatal("unmatched auth route returned an HTTP/3 response")
	}
	resp, err := client.Get("https://app.example.test/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || resp.ProtoMajor != 3 {
		t.Fatalf("valid auth route response = %#v", resp)
	}
}
