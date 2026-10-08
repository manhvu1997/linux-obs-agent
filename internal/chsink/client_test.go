package chsink

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/manhvu1997/linux-obs-agent/internal/config"
)

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

func testClient(t *testing.T, url string) *Client {
	t.Helper()
	c, err := NewClient(&config.ClickHouseConfig{URL: url, Database: "obs", Username: "u", Password: "p", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestInsertRequestShape(t *testing.T) {
	var gotQuery, gotEnc, gotUser, gotPass, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		gotQuery = q.Get("query") + "|" + q.Get("async_insert") + "|" + q.Get("wait_for_async_insert")
		gotEnc = r.Header.Get("Content-Encoding")
		gotUser, gotPass, _ = r.BasicAuth()
		zr, err := gzip.NewReader(r.Body)
		if err == nil {
			b, _ := io.ReadAll(zr)
			gotBody = string(b)
		}
	}))
	defer srv.Close()

	out, err := testClient(t, srv.URL).Insert(context.Background(), TableDigestStats, gz(t, "{\"a\":1}\n"))
	if out != OutcomeOK || err != nil {
		t.Fatalf("Insert = %v, %v", out, err)
	}
	if gotQuery != "INSERT INTO obs.mysql_digest_stats FORMAT JSONEachRow|1|1" {
		t.Errorf("query = %q", gotQuery)
	}
	if gotEnc != "gzip" || gotUser != "u" || gotPass != "p" || gotBody != "{\"a\":1}\n" {
		t.Errorf("enc=%q user=%q pass=%q body=%q", gotEnc, gotUser, gotPass, gotBody)
	}
}

func TestInsertClassification(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   Outcome
	}{
		{200, "", OutcomeOK},
		{401, "Code: 516. Authentication failed", OutcomeReject},
		{404, "Code: 60. Table obs.x does not exist", OutcomeReject},
		{400, "Code: 202. TOO_MANY_SIMULTANEOUS_QUERIES", OutcomeRetry},
		{429, "", OutcomeRetry},
		{500, "", OutcomeRetry},
		{503, "", OutcomeRetry},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		out, err := testClient(t, srv.URL).Insert(context.Background(), TableFamilyStats, gz(t, "{}\n"))
		srv.Close()
		if out != tc.want {
			t.Errorf("status %d body %q: outcome %v, want %v (err %v)", tc.status, tc.body, out, tc.want, err)
		}
		if tc.want != OutcomeOK && (err == nil || !strings.Contains(err.Error(), "HTTP")) {
			t.Errorf("status %d: err = %v, want an HTTP error", tc.status, err)
		}
	}
}

func TestInsertNetworkErrorRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	if out, err := testClient(t, url).Insert(context.Background(), TableFamilyStats, gz(t, "{}\n")); out != OutcomeRetry || err == nil {
		t.Fatalf("closed server: %v, %v", out, err)
	}
}

func TestPing(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("query") != "SELECT 1" {
			w.WriteHeader(400)
		}
	}))
	defer ok.Close()
	if err := testClient(t, ok.URL).Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer bad.Close()
	if err := testClient(t, bad.URL).Ping(context.Background()); err == nil {
		t.Fatal("ping against 401 must fail")
	}
}
