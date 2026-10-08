package chsink

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
)

// Outcome tells the sink what to do with a batch after an insert attempt.
type Outcome int

const (
	OutcomeOK     Outcome = iota // delivered: remove from the buffer
	OutcomeRetry                 // transient: keep and retry next cycle
	OutcomeReject                // permanent (auth, schema): drop and count
)

// Client speaks ClickHouse's HTTP interface. No driver dependency keeps the
// binary static (no CGO).
type Client struct {
	endpoint   string
	db         string
	user, pass string
	hc         *http.Client
}

func NewClient(cfg *config.ClickHouseConfig) (*Client, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("clickhouse.url: %w", err)
	}
	u.RawQuery, u.Fragment = "", ""
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TLSInsecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in
	}
	return &Client{
		endpoint: strings.TrimRight(u.String(), "/") + "/",
		db:       cfg.Database, user: cfg.Username, pass: cfg.Password,
		hc: &http.Client{Timeout: cfg.Timeout, Transport: tr},
	}, nil
}

// Insert posts one gzip-compressed JSONEachRow batch. table must be one of
// the Table* constants and the database is validated at config load, so the
// query string is never built from untrusted input.
func (c *Client) Insert(ctx context.Context, table string, gz []byte) (Outcome, error) {
	q := url.Values{}
	q.Set("query", "INSERT INTO "+c.db+"."+table+" FORMAT JSONEachRow")
	q.Set("async_insert", "1")
	q.Set("wait_for_async_insert", "1")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"?"+q.Encode(), bytes.NewReader(gz))
	if err != nil {
		return OutcomeReject, err
	}
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/x-ndjson")
	return c.do(req)
}

// Ping runs SELECT 1 with the configured credentials.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"?"+url.Values{"query": {"SELECT 1"}}.Encode(), nil)
	if err != nil {
		return err
	}
	_, err = c.do(req)
	return err
}

func (c *Client) do(req *http.Request) (Outcome, error) {
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return OutcomeRetry, fmt.Errorf("clickhouse: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return classify(resp.StatusCode, string(body))
}

func classify(status int, body string) (Outcome, error) {
	if status >= 200 && status < 300 {
		return OutcomeOK, nil
	}
	retry := status == http.StatusTooManyRequests || status >= 500 ||
		strings.Contains(body, "TOO_MANY_SIMULTANEOUS_QUERIES")
	if len(body) > 512 {
		body = body[:512]
	}
	err := fmt.Errorf("clickhouse: HTTP %d: %s", status, strings.TrimSpace(body))
	if retry {
		return OutcomeRetry, err
	}
	return OutcomeReject, err
}
