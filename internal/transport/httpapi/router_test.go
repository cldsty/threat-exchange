package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"threat-exchange/internal/api"
	"threat-exchange/internal/auth"
	"threat-exchange/internal/domain/threat"
	"threat-exchange/internal/observability"
	"threat-exchange/internal/ratelimit"
	"threat-exchange/internal/service"
	"threat-exchange/internal/storage/memory"
	"threat-exchange/internal/transport/httpapi"
)

const (
	readerKey  = "tx_reader_key"
	writerKey  = "tx_writer_key"
	partnerKey = "tx_partner_key"
	md5        = "d41d8cd98f00b204e9800998ecf8427e"
)

var fixedNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

type env struct {
	t       *testing.T
	handler http.Handler
	metrics *observability.Metrics
	logs    *bytes.Buffer
}

type option func(*httpapi.Config)

func newEnv(t *testing.T, opts ...option) *env {
	t.Helper()
	keys, err := auth.ParseKeyStore("reader:reader:" + auth.HashKey(readerKey) +
		",writer:writer:" + auth.HashKey(writerKey) + ",partner:writer:" + auth.HashKey(partnerKey))
	require.NoError(t, err)
	clock := func() time.Time { return fixedNow }
	logs := &bytes.Buffer{}
	cfg := httpapi.Config{
		Service:       service.New(memory.New(clock), service.ClockFunc(clock)),
		Authenticator: keys,
		MaxBodyBytes:  4 << 10,
		Logger:        slog.New(observability.NewLogHandler(slog.NewJSONHandler(logs, nil))),
		Metrics:       observability.NewMetrics(),
	}
	for _, o := range opts {
		o(&cfg)
	}
	h, err := httpapi.NewHandler(cfg)
	require.NoError(t, err)
	return &env{t: t, handler: h, metrics: cfg.Metrics, logs: logs}
}

type response struct {
	*http.Response
	body []byte
}

func (r response) errorBody(t *testing.T) api.ErrorResponse {
	t.Helper()
	var e api.ErrorResponse
	require.NoError(t, json.Unmarshal(r.body, &e), string(r.body))
	return e
}

func (r response) threat(t *testing.T) api.ThreatResponse {
	t.Helper()
	var v api.ThreatResponse
	require.NoError(t, json.Unmarshal(r.body, &v), string(r.body))
	return v
}

func (e *env) do(method, path, key, body string, headers ...string) response {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set(auth.HeaderAPIKey, key)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	res := rec.Result()
	b, err := io.ReadAll(res.Body)
	require.NoError(e.t, err)
	return response{Response: res, body: b}
}

func (e *env) create(body string) response {
	e.t.Helper()
	r := e.do(http.MethodPost, "/info", writerKey, body)
	require.Equal(e.t, http.StatusCreated, r.StatusCode, string(r.body))
	return r
}

func fieldsOf(e api.ErrorResponse) []string {
	if e.Fields == nil {
		return nil
	}
	var out []string
	for _, f := range *e.Fields {
		out = append(out, f.Field)
	}
	return out
}

func TestCreateAndGet(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	created := e.create(`{
		"md5": "D41D8CD98F00B204E9800998ECF8427E",
		"sha256": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
		"name": "Trojan.Win32.Generic",
		"description": "Downloads modules",
		"types": ["trojan", "downloader"],
		"zone": "red",
		"severity": "high",
		"file_size": 73802,
		"first_seen_at": "2026-01-15T13:30:00+03:00",
		"last_seen_at": "2026-02-01T00:00:00Z"
	}`)
	assert.Equal(t, `"1"`, created.Header.Get("ETag"))
	assert.Equal(t, "/info/"+md5, created.Header.Get("Location"))
	assert.Equal(t, "application/json", created.Header.Get("Content-Type"))

	got := created.threat(t)
	assert.Equal(t, md5, got.Md5, "MD5 normalized to lower case")
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", *got.Sha256)
	assert.Equal(t, api.ThreatTypes{"trojan", "downloader"}, got.Types)
	assert.Equal(t, api.ZoneRed, got.Zone)
	assert.Equal(t, api.TlpAmber, got.Tlp, "default label")
	assert.Equal(t, api.High, got.Severity)
	assert.Equal(t, time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC), *got.FirstSeenAt, "stored in UTC")
	assert.Equal(t, "writer", got.CreatedBy)
	assert.Nil(t, got.Sha1, "absent optional fields are omitted")
	assert.NotContains(t, string(created.body), `"version"`, "the version is exposed only as ETag")
	assert.NotContains(t, string(created.body), `"sha1"`)

	fetched := e.do(http.MethodGet, "/info/"+strings.ToUpper(md5), readerKey, "")
	require.Equal(t, http.StatusOK, fetched.StatusCode, string(fetched.body))
	assert.Equal(t, `"1"`, fetched.Header.Get("ETag"))
	assert.Equal(t, got, fetched.threat(t))
}

func TestCreateWithOriginalContractOnly(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	got := e.create(`{"md5":"` + md5 + `","name":"Trojan.Win32.Generic"}`).threat(t)
	assert.Equal(t, api.ZoneGrey, got.Zone)
	assert.Equal(t, api.Unknown, got.Severity)
	assert.False(t, got.Revoked)
	assert.Equal(t, api.ThreatTypes{}, got.Types)
}

func TestCreateConflict(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.create(`{"md5":"` + md5 + `","name":"A"}`)
	r := e.do(http.MethodPost, "/info", writerKey, `{"md5":"`+strings.ToUpper(md5)+`","name":"B"}`)
	assert.Equal(t, http.StatusConflict, r.StatusCode)
	eb := r.errorBody(t)
	assert.Equal(t, api.ErrorResponseCodeConflict, eb.Code)
	assert.NotNil(t, eb.RequestId)
}

func TestCreateValidation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tests := []struct {
		name   string
		body   string
		fields []string
	}{
		{"missing md5", `{"name":"X"}`, []string{"md5"}},
		{"missing name", `{"md5":"` + md5 + `"}`, []string{"name"}},
		{"md5 too short", `{"md5":"abc","name":"X"}`, []string{"md5"}},
		{"md5 not hex", `{"md5":"` + strings.Repeat("z", 32) + `","name":"X"}`, []string{"md5"}},
		{"unknown field", `{"md5":"` + md5 + `","name":"X","colour":"red"}`, []string{"body"}},
		{"name with spaces around", `{"md5":"` + md5 + `","name":" X "}`, []string{"name"}},
		{"name too long", `{"md5":"` + md5 + `","name":"` + strings.Repeat("a", 256) + `"}`, []string{"name"}},
		{"whitespace description", `{"md5":"` + md5 + `","name":"X","description":"   "}`, []string{"description"}},
		{"unknown type", `{"md5":"` + md5 + `","name":"X","types":["Trojan"]}`, []string{"types.0"}},
		{"duplicate types", `{"md5":"` + md5 + `","name":"X","types":["worm","worm"]}`, []string{"types"}},
		{"bad zone", `{"md5":"` + md5 + `","name":"X","zone":"blue"}`, []string{"zone"}},
		{"bad severity", `{"md5":"` + md5 + `","name":"X","severity":"extreme"}`, []string{"severity"}},
		{"negative size", `{"md5":"` + md5 + `","name":"X","file_size":-1}`, []string{"file_size"}},
		{"date without zone", `{"md5":"` + md5 + `","name":"X","first_seen_at":"2026-01-01T00:00:00"}`, []string{"first_seen_at"}},
		{"wrong type", `{"md5":"` + md5 + `","name":"X","revoked":"yes"}`, []string{"revoked"}},
		// Rules that span several fields are enforced by the domain layer.
		{"severity for grey zone", `{"md5":"` + md5 + `","name":"X","severity":"high"}`, []string{"severity"}},
		{"last before first", `{"md5":"` + md5 + `","name":"X","first_seen_at":"2026-02-01T00:00:00Z","last_seen_at":"2026-01-01T00:00:00Z"}`, []string{"last_seen_at"}},
		{"future date", `{"md5":"` + md5 + `","name":"X","last_seen_at":"2027-01-01T00:00:00Z"}`, []string{"last_seen_at"}},
		{"date before the minimum", `{"md5":"` + md5 + `","name":"X","first_seen_at":"1969-12-31T23:59:59Z"}`, []string{"first_seen_at"}},
		{"year below zero after UTC conversion", `{"md5":"` + md5 + `","name":"X","first_seen_at":"0000-01-01T00:00:00+14:00"}`, []string{"first_seen_at"}},
		{"zero-width name", `{"md5":"` + md5 + `","name":"\u200b"}`, []string{"name"}},
		{"bidi override in name", `{"md5":"` + md5 + `","name":"Trojan\u202eexe.txt"}`, []string{"name"}},
		{"bidi override in description", `{"md5":"` + md5 + `","name":"X","description":"a\u202eb"}`, []string{"description"}},
		{"unknown tlp", `{"md5":"` + md5 + `","name":"X","tlp":"white"}`, []string{"tlp"}},
		{"confidence above range", `{"md5":"` + md5 + `","name":"X","confidence":101}`, []string{"confidence"}},
		{"negative confidence", `{"md5":"` + md5 + `","name":"X","confidence":-1}`, []string{"confidence"}},
		{"several problems", `{"md5":"x","name":" X","zone":"blue"}`, []string{"md5", "name", "zone"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := e.do(http.MethodPost, "/info", writerKey, tt.body)
			require.Equal(t, http.StatusBadRequest, r.StatusCode, string(r.body))
			eb := r.errorBody(t)
			assert.Equal(t, api.ErrorResponseCodeValidationFailed, eb.Code)
			assert.ElementsMatch(t, tt.fields, fieldsOf(eb), string(r.body))
		})
	}
}

func TestMalformedRequests(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	r := e.do(http.MethodPost, "/info", writerKey, `{"md5":`)
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)

	r = e.do(http.MethodPost, "/info", writerKey, "")
	assert.Equal(t, http.StatusBadRequest, r.StatusCode, "body is required")

	r = e.do(http.MethodPost, "/info", writerKey, `{"md5":"`+md5+`","name":"X"}`, "Content-Type", "text/plain")
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
}

func TestGetErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)

	r := e.do(http.MethodGet, "/info/"+md5, readerKey, "")
	assert.Equal(t, http.StatusNotFound, r.StatusCode)
	eb := r.errorBody(t)
	assert.Equal(t, api.ErrorResponseCodeNotFound, eb.Code)
	assert.Equal(t, "Threat not found", eb.Message)
	assert.Equal(t, "No threat with MD5 "+md5+" found", *eb.Details)

	r = e.do(http.MethodGet, "/info/not-an-md5", readerKey, "")
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
	assert.Equal(t, []string{"md5"}, fieldsOf(r.errorBody(t)))
}

func TestRoutingErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := e.do(http.MethodGet, "/unknown", readerKey, "")
	assert.Equal(t, http.StatusNotFound, r.StatusCode)

	r = e.do(http.MethodDelete, "/info/"+md5, writerKey, "")
	assert.Equal(t, http.StatusMethodNotAllowed, r.StatusCode)
	assert.Equal(t, api.ErrorResponseCodeMethodNotAllowed, r.errorBody(t).Code)
}

func TestReplace(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.create(`{"md5":"` + md5 + `","name":"Old","zone":"red","severity":"high","types":["worm"],"description":"d"}`)

	r := e.do(http.MethodPut, "/info/"+strings.ToUpper(md5), writerKey, `{"name":"New","revoked":true}`)
	require.Equal(t, http.StatusOK, r.StatusCode, string(r.body))
	assert.Equal(t, `"2"`, r.Header.Get("ETag"))
	got := r.threat(t)
	assert.Equal(t, "New", got.Name)
	assert.True(t, got.Revoked)
	assert.Equal(t, api.ZoneGrey, got.Zone, "PUT is a full replacement")
	assert.Equal(t, api.Unknown, got.Severity)
	assert.Empty(t, got.Types)
	assert.Nil(t, got.Description)
}

func TestSharedRecordBetweenOrganizations(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	created := e.create(`{"md5":"` + md5 + `","name":"From A","zone":"red","severity":"high","tlp":"green","confidence":90}`)
	got := created.threat(t)
	assert.Equal(t, api.TlpGreen, got.Tlp)
	assert.EqualValues(t, 90, *got.Confidence)

	// Organization B cannot create a second record...
	r := e.do(http.MethodPost, "/info", partnerKey, `{"md5":"`+md5+`","name":"From B"}`)
	assert.Equal(t, http.StatusConflict, r.StatusCode)

	// ...and cannot overwrite the data of A without having read it.
	for _, headers := range [][]string{nil, {"If-Match", "*"}} {
		r = e.do(http.MethodPut, "/info/"+md5, partnerKey, `{"name":"From B"}`, headers...)
		require.Equal(t, http.StatusPreconditionRequired, r.StatusCode, string(r.body))
		assert.Equal(t, api.ErrorResponseCodePreconditionRequired, r.errorBody(t).Code)
	}

	// It reads the record, merges the data and replaces it with the version.
	read := e.do(http.MethodGet, "/info/"+md5, partnerKey, "")
	r = e.do(http.MethodPut, "/info/"+md5, partnerKey, `{"name":"Merged","zone":"red","severity":"high"}`,
		"If-Match", read.Header.Get("ETag"))
	require.Equal(t, http.StatusOK, r.StatusCode, string(r.body))
	got = r.threat(t)
	assert.Equal(t, "writer", got.CreatedBy)
	assert.Equal(t, "partner", got.UpdatedBy)

	// Now A is the one who has to read the record first.
	r = e.do(http.MethodPut, "/info/"+md5, writerKey, `{"name":"From A again"}`)
	assert.Equal(t, http.StatusPreconditionRequired, r.StatusCode)
}

func TestSHA256Conflict(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	sha := strings.Repeat("a", 64)
	other := strings.Repeat("b", 32)
	e.create(`{"md5":"` + md5 + `","name":"X","sha256":"` + sha + `"}`)

	r := e.do(http.MethodPost, "/info", writerKey, `{"md5":"`+other+`","name":"Y","sha256":"`+sha+`"}`)
	assert.Equal(t, http.StatusConflict, r.StatusCode, string(r.body))
	assert.Equal(t, "SHA-256 belongs to another threat", r.errorBody(t).Message)

	e.create(`{"md5":"` + other + `","name":"Y"}`)
	r = e.do(http.MethodPut, "/info/"+other, writerKey, `{"name":"Y","sha256":"`+sha+`"}`)
	assert.Equal(t, http.StatusConflict, r.StatusCode, string(r.body))
}

func TestReplaceErrors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.create(`{"md5":"` + md5 + `","name":"Old"}`)

	tests := []struct {
		name    string
		path    string
		body    string
		headers []string
		status  int
		code    api.ErrorResponseCode
	}{
		{"not found", "/info/ffffffffffffffffffffffffffffffff", `{"name":"X"}`, nil, 404, api.ErrorResponseCodeNotFound},
		{"md5 in body is rejected", "/info/" + md5, `{"md5":"` + md5 + `","name":"X"}`, nil, 400, api.ErrorResponseCodeValidationFailed},
		{"missing name", "/info/" + md5, `{}`, nil, 400, api.ErrorResponseCodeValidationFailed},
		{"bad path md5", "/info/xyz", `{"name":"X"}`, nil, 400, api.ErrorResponseCodeValidationFailed},
		{"stale If-Match", "/info/" + md5, `{"name":"X"}`, []string{"If-Match", `"7"`}, 412, api.ErrorResponseCodePreconditionFailed},
		{"malformed If-Match", "/info/" + md5, `{"name":"X"}`, []string{"If-Match", "1"}, 400, api.ErrorResponseCodeValidationFailed},
		{"weak If-Match", "/info/" + md5, `{"name":"X"}`, []string{"If-Match", `W/"1"`}, 400, api.ErrorResponseCodeValidationFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := e.do(http.MethodPut, tt.path, writerKey, tt.body, tt.headers...)
			require.Equal(t, tt.status, r.StatusCode, string(r.body))
			assert.Equal(t, tt.code, r.errorBody(t).Code)
		})
	}

	t.Run("matching If-Match and wildcard succeed", func(t *testing.T) {
		r := e.do(http.MethodPut, "/info/"+md5, writerKey, `{"name":"V2"}`, "If-Match", `"1"`)
		require.Equal(t, http.StatusOK, r.StatusCode, string(r.body))
		r = e.do(http.MethodPut, "/info/"+md5, writerKey, `{"name":"V3"}`, "If-Match", "*")
		require.Equal(t, http.StatusOK, r.StatusCode, string(r.body))
		assert.Equal(t, `"3"`, r.Header.Get("ETag"))
		r = e.do(http.MethodPut, "/info/"+md5, writerKey, `{"name":"V4"}`, "If-Match", `"2", "3"`)
		require.Equal(t, http.StatusOK, r.StatusCode, "a list of entity tags is accepted: %s", r.body)
		assert.Equal(t, `"4"`, r.Header.Get("ETag"))
	})
}

func TestAuthentication(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, key := range []string{"", "wrong-key"} {
		r := e.do(http.MethodGet, "/info/"+md5, key, "")
		assert.Equal(t, http.StatusUnauthorized, r.StatusCode)
		assert.Equal(t, api.ErrorResponseCodeUnauthorized, r.errorBody(t).Code)
		assert.Contains(t, r.Header.Get("WWW-Authenticate"), auth.HeaderAPIKey)
	}
	r := e.do(http.MethodGet, "/unknown", "", "")
	assert.Equal(t, http.StatusUnauthorized, r.StatusCode, "routes are not revealed to anonymous clients")

	assert.InDelta(t, 2, testutil.ToFloat64(e.metrics.AuthFailuresTotal.WithLabelValues("missing")), 0)
	assert.InDelta(t, 1, testutil.ToFloat64(e.metrics.AuthFailuresTotal.WithLabelValues("invalid")), 0)
	assert.NotContains(t, e.logs.String(), "wrong-key", "keys are never logged")
}

func TestAuthorization(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := e.do(http.MethodPost, "/info", readerKey, `{"md5":"`+md5+`","name":"X"}`)
	assert.Equal(t, http.StatusForbidden, r.StatusCode)
	assert.Equal(t, api.ErrorResponseCodeForbidden, r.errorBody(t).Code)

	r = e.do(http.MethodPut, "/info/"+md5, readerKey, `{"name":"X"}`)
	assert.Equal(t, http.StatusForbidden, r.StatusCode)

	// Authorization happens before validation: an invalid body still gets 403.
	r = e.do(http.MethodPost, "/info", readerKey, `{"bad":true}`)
	assert.Equal(t, http.StatusForbidden, r.StatusCode)
}

func TestBodyLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	big := `{"md5":"` + md5 + `","name":"X","description":"` + strings.Repeat("a", 5000) + `"}`
	r := e.do(http.MethodPost, "/info", writerKey, big)
	assert.Equal(t, http.StatusRequestEntityTooLarge, r.StatusCode)
	assert.Equal(t, api.ErrorResponseCodePayloadTooLarge, r.errorBody(t).Code)
}

func TestRateLimitPerKey(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(c *httpapi.Config) {
		c.KeyLimiter = ratelimit.New(ratelimit.Config{Rate: 0.001, Burst: 2})
	})
	for range 2 {
		assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, "/info/"+md5, readerKey, "").StatusCode)
	}
	r := e.do(http.MethodGet, "/info/"+md5, readerKey, "")
	assert.Equal(t, http.StatusTooManyRequests, r.StatusCode)
	assert.Equal(t, api.ErrorResponseCodeRateLimited, r.errorBody(t).Code)
	assert.NotEmpty(t, r.Header.Get("Retry-After"))

	assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, "/info/"+md5, writerKey, "").StatusCode,
		"other keys are not affected")
	assert.InDelta(t, 1, testutil.ToFloat64(e.metrics.RateLimitedTotal.WithLabelValues("key")), 0)
}

func TestRateLimitPerIPAppliesBeforeAuthentication(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(c *httpapi.Config) {
		c.IPLimiter = ratelimit.New(ratelimit.Config{Rate: 0.001, Burst: 3})
	})
	for range 3 {
		assert.Equal(t, http.StatusUnauthorized, e.do(http.MethodGet, "/info/"+md5, "guess", "").StatusCode)
	}
	assert.Equal(t, http.StatusTooManyRequests, e.do(http.MethodGet, "/info/"+md5, "guess", "").StatusCode,
		"brute-forcing keys is throttled")
}

func TestSecurityHeadersAndRequestID(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	r := e.do(http.MethodGet, "/info/"+md5, readerKey, "")
	assert.Equal(t, "nosniff", r.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "no-store", r.Header.Get("Cache-Control"))
	assert.Equal(t, "DENY", r.Header.Get("X-Frame-Options"))
	assert.Contains(t, r.Header.Get("Content-Security-Policy"), "default-src 'none'")
	assert.Empty(t, r.Header.Get("Strict-Transport-Security"), "HSTS only over TLS")

	id := r.Header.Get(httpapi.HeaderRequestID)
	assert.NotEmpty(t, id)
	assert.Equal(t, id, *r.errorBody(t).RequestId, "request ID is in the error body for support")

	r = e.do(http.MethodGet, "/info/"+md5, readerKey, "", httpapi.HeaderRequestID, "trace-123")
	assert.Equal(t, "trace-123", r.Header.Get(httpapi.HeaderRequestID), "well-formed incoming ID is kept")

	r = e.do(http.MethodGet, "/info/"+md5, readerKey, "", httpapi.HeaderRequestID, "bad id\x01")
	assert.NotEqual(t, "bad id\x01", r.Header.Get(httpapi.HeaderRequestID), "malformed incoming ID is replaced")
}

func TestAccessLogAndMetrics(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.do(http.MethodGet, "/info/"+md5, readerKey, "")

	assert.InDelta(t, 1, testutil.ToFloat64(
		e.metrics.RequestsTotal.WithLabelValues("GET", "GET /info/{md5}", "404")), 0)

	var entry map[string]any
	for _, line := range strings.Split(strings.TrimSpace(e.logs.String()), "\n") {
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		if entry["msg"] == "http request" {
			break
		}
	}
	assert.Equal(t, "http request", entry["msg"])
	assert.Equal(t, "reader", entry["principal"])
	assert.EqualValues(t, 404, entry["status"])
	assert.Equal(t, "GET /info/{md5}", entry["route"])
	assert.Equal(t, "192.0.2.1", entry["client_ip"])
}

func TestLogsCarryRequestID(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(c *httpapi.Config) { c.Service = failingService{} })
	r := e.do(http.MethodGet, "/info/"+md5, readerKey, "", httpapi.HeaderRequestID, "trace-42")
	assert.Equal(t, "trace-42", *r.errorBody(t).RequestId)

	seen := map[any]bool{}
	for _, line := range strings.Split(strings.TrimSpace(e.logs.String()), "\n") {
		var entry map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		assert.Equal(t, "trace-42", entry["request_id"], line)
		seen[entry["msg"]] = true
	}
	assert.True(t, seen["request failed"], "the failure can be found by the ID given to the client")
	assert.True(t, seen["http request"], "so can the access log entry")
}

func TestMetricsDoNotGrowWithArbitraryMethods(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, method := range []string{"AAA", "BBB", "CCC"} {
		assert.Equal(t, http.StatusUnauthorized, e.do(method, "/x", "", "").StatusCode)
	}
	assert.Equal(t, 1, testutil.CollectAndCount(e.metrics.RequestsTotal), "unknown methods share one label")
	assert.InDelta(t, 3, testutil.ToFloat64(e.metrics.RequestsTotal.WithLabelValues("OTHER", "unmatched", "401")), 0)
}

type panickingService struct{ httpapi.ThreatService }

func (panickingService) Get(context.Context, string) (threat.Threat, error) { panic("boom") }

type failingService struct{ httpapi.ThreatService }

func (failingService) Get(context.Context, string) (threat.Threat, error) {
	return threat.Threat{}, errors.New("connection refused: password=secret")
}

func TestPanicIsRecovered(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(c *httpapi.Config) { c.Service = panickingService{} })
	r := e.do(http.MethodGet, "/info/"+md5, readerKey, "")
	assert.Equal(t, http.StatusInternalServerError, r.StatusCode)
	assert.Equal(t, api.ErrorResponseCodeInternal, r.errorBody(t).Code)
	assert.InDelta(t, 1, testutil.ToFloat64(e.metrics.PanicsTotal), 0)
	assert.InDelta(t, 1, testutil.ToFloat64(
		e.metrics.RequestsTotal.WithLabelValues("GET", "GET /info/{md5}", "500")), 0, "panics count as 500s")
	assert.Contains(t, e.logs.String(), `"msg":"http request"`, "and reach the access log")
}

func TestInternalErrorsAreNotLeaked(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(c *httpapi.Config) { c.Service = failingService{} })
	r := e.do(http.MethodGet, "/info/"+md5, readerKey, "")
	assert.Equal(t, http.StatusInternalServerError, r.StatusCode)
	assert.NotContains(t, string(r.body), "password")
	assert.Equal(t, "Internal server error", r.errorBody(t).Message)
	assert.Contains(t, e.logs.String(), "connection refused", "details go to the log")
}

func TestNewHandlerRequiresDependencies(t *testing.T) {
	t.Parallel()
	_, err := httpapi.NewHandler(httpapi.Config{})
	assert.Error(t, err)
}

func TestClientIPLimitKey(t *testing.T) {
	t.Parallel()
	c := httpapi.NewClientIP(nil)
	tests := []struct{ name, remote, want string }{
		{"ipv4 stays an address", "203.0.113.7:5000", "203.0.113.7"},
		{"ipv6 is reduced to /64", "[2001:db8:1:2:3:4:5:6]:443", "2001:db8:1:2::/64"},
		{"another address of the same /64", "[2001:db8:1:2:aaaa::1]:443", "2001:db8:1:2::/64"},
		{"mapped ipv4", "[::ffff:203.0.113.7]:443", "203.0.113.7"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			assert.Equal(t, tt.want, c.LimitKey(r))
		})
	}
}

func TestClientIP(t *testing.T) {
	t.Parallel()
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	c := httpapi.NewClientIP(trusted)
	tests := []struct {
		name, remote, xff, want string
	}{
		{"direct client", "203.0.113.7:5000", "", "203.0.113.7"},
		{"untrusted peer ignores XFF", "203.0.113.7:5000", "1.1.1.1", "203.0.113.7"},
		{"trusted proxy", "10.0.0.5:443", "198.51.100.1", "198.51.100.1"},
		{"spoofed prefix is ignored", "10.0.0.5:443", "6.6.6.6, 198.51.100.1", "198.51.100.1"},
		{"chain of trusted proxies", "10.0.0.5:443", "198.51.100.1, 10.1.1.1", "198.51.100.1"},
		{"garbage XFF", "10.0.0.5:443", "not-an-ip", "10.0.0.5"},
		{"ipv6", "[2001:db8::1]:443", "", "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remote
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			assert.Equal(t, tt.want, c.Resolve(r))
		})
	}
}
