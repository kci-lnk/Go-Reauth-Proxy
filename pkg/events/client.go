package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const internalSystemEventsPath = "/api/internal/system-events"
const defaultSystemEventsPort = 7998

type Client struct {
	httpClient *http.Client
}

func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.MaxIdleConns = 32
		transport.MaxIdleConnsPerHost = 32
		transport.IdleConnTimeout = 30 * time.Second
		transport.DialContext = (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext
		httpClient = &http.Client{
			Timeout:   2 * time.Second,
			Transport: transport,
		}
	}

	return &Client{httpClient: httpClient}
}

func (c *Client) Publish(
	ctx context.Context,
	targetPort int,
	input SystemEventPublishInput,
) error {
	if c == nil {
		return fmt.Errorf("system event client is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	client := c.httpClient
	if client == nil {
		client = NewClient(nil).httpClient
	}

	body, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("marshal system event payload: %w", err)
	}

	port := resolveSystemEventPort(targetPort)
	url := localSystemEventsURL(port)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create system event request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send system event request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}

	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_, _ = io.Copy(io.Discard, resp.Body)
	message := strings.TrimSpace(string(responseBody))
	if message == "" {
		message = http.StatusText(resp.StatusCode)
	}

	return fmt.Errorf(
		"system event endpoint returned %d: %s",
		resp.StatusCode,
		message,
	)
}

func resolveSystemEventPort(targetPort int) int {
	if targetPort > 0 {
		return targetPort
	}

	envCandidates := []string{
		"BACKEND_PORT",
		"FN_INTERNAL_EVENTS_PORT",
	}

	for _, key := range envCandidates {
		value := strings.TrimSpace(os.Getenv(key))
		if value == "" {
			continue
		}
		port, err := strconv.Atoi(value)
		if err == nil && port > 0 && port <= 65535 {
			return port
		}
	}

	return defaultSystemEventsPort
}

const localSystemEventsURLPrefix = "http://127.0.0.1:"

func localSystemEventsURL(port int) string {
	var stack [len(localSystemEventsURLPrefix) + 20 + len(internalSystemEventsPath)]byte
	buf := stack[:0]
	buf = append(buf, localSystemEventsURLPrefix...)
	buf = strconv.AppendInt(buf, int64(port), 10)
	buf = append(buf, internalSystemEventsPath...)
	return string(buf)
}
