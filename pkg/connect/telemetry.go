package connect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Telemetry contains http request header telemetry fields for logging purposes
type Telemetry struct {
	Traceparent Traceparent `json:"traceparent,omitempty"` // refers to the W3C traceparent header fields
	Protocol    string      `json:"protocol,omitempty"`    // refers to the http protocol version
	Method      string      `json:"method,omitempty"`      // refers to the http request method
	Path        string      `json:"path,omitempty"`        // refers to the http request path
	RemoteAddr  string      `json:"remote_addr,omitempty"` // refers to the remote address of the client
	UserAgent   string      `json:"user_agent,omitempty"`  // refers to the user agent of the client
	Host        string      `json:"host,omitempty"`        // refers to the host header of the request
	Referrer    string      `json:"referrer,omitempty"`    // refers to the referrer header of the request
	StartTime   time.Time   `json:"start_time,omitempty"`  // refers to the time the request was received
}

// NewTelemetry creates a new Telemetry struct from an http request,
// AND also generates a new Traceparent to send to service calls.
// NOTE: this function is intended for gateway services that do not expect a
// traceparent header from the client.  Internal services should use ObtainTelemetry instead,
// which will attempt to parse the traceparent header and generate a new one if it is not present or invalid.
func NewTelemetry(r *http.Request, logger *slog.Logger) *Telemetry {

	// check if logger is nil and set to default if so
	if logger == nil {
		logger = slog.Default()
	}

	traceParent := GenerateTraceParent()
	protocol := validate.SanitizeProtocol(r.Proto)
	method := validate.SanitizeMethod(r.Method)
	path := validate.SanitizePath(r.URL.Path)
	remoteAddr := validate.SanitizeIp(getClientIp(r))
	userAgent := validate.SanitizeUserAgent(r.UserAgent())
	host := validate.SanitizeHost(r.Host)
	referrer := validate.SanitizeReferrer(r.Referer())
	startTime := time.Now()

	logger.Info("creating new telemetry for incoming request",
		slog.String("trace_id", traceParent.TraceId),
		slog.String("span_id", traceParent.SpanId),
		slog.String("protocol", protocol),
		slog.String("method", method),
		slog.String("protocol", protocol),
		slog.String("method", method),
		slog.String("path", path),
		slog.String("remote_addr", remoteAddr),
		slog.String("user_agent", userAgent),
		slog.String("host", host),
		slog.String("referrer", startTime.Format(time.RFC3339)),
	)

	return &Telemetry{
		Traceparent: *traceParent,
		Protocol:    protocol,
		Method:      method,
		Path:        path,
		RemoteAddr:  remoteAddr,
		UserAgent:   userAgent,
		Host:        host,
		Referrer:    referrer,
		StartTime:   startTime,
	}
}

// TelemetryFields adds telemetry fields to the logger from the Telemetry struct in context
func (t *Telemetry) TelemetryFields() []any {

	fields := []any{
		slog.String("trace_id", t.Traceparent.TraceId),
		slog.String("span_id", t.Traceparent.SpanId),
		// other fields will only be present if the origin of the request is
		// a web call, vs a scheduled job.
	}

	// Add parent span id if it exists
	if t.Traceparent.ParentSpanId != "" {
		fields = append(fields, slog.String("parent_span_id", t.Traceparent.ParentSpanId))
	}

	// Add web call fields if they exist
	if t.Protocol != "" {
		fields = append(fields, slog.String("protocol", t.Protocol))
	}

	if t.Method != "" {
		fields = append(fields, slog.String("method", t.Method))
	}

	if t.Path != "" {
		fields = append(fields, slog.String("path", t.Path))
	}

	if t.RemoteAddr != "" {
		fields = append(fields, slog.String("remote_addr", t.RemoteAddr))
	}

	if t.UserAgent != "" {
		fields = append(fields, slog.String("user_agent", t.UserAgent))
	}

	if t.Host != "" {
		fields = append(fields, slog.String("host", t.Host))
	}

	if t.Referrer != "" {
		fields = append(fields, slog.String("referrer", t.Referrer))
	}

	// status code and duration added by defer method later

	return fields
}

// TraceparentVersion is the version of the W3C traceparent header: used as default
const TraceparentVersion string = "00"

// Traceparent is a struct representing the W3C traceparent header
type Traceparent struct {
	Version      string `json:"version"`                  // refers to the version of the telemetry schema
	TraceId      string `json:"transaction_id"`           // refers to the overall transaction across services
	ParentSpanId string `json:"parent_span_id,omitempty"` // refers to the caller of the current service -> span id of the caller
	SpanId       string `json:"span_id"`                  // refers to the current operation in the current service
	Flags        string `json:"flags"`
}

// BuildTraceparent builds a W3C traceparent header value from the Telemetry fields.
// It will check if the values exist, but if they do, it assumes they are valid.
func (t *Traceparent) BuildTraceparent(logger *slog.Logger) string {

	log := logger

	// check for missing fields and generate new ones if necessary but this should not happen
	if t.Version == "" {
		t.Version = TraceparentVersion
		log = log.With(slog.String("new_version", t.Version))
	}

	if t.TraceId == "" {
		t.TraceId = GenerateTraceId()
		log = log.With(slog.String("new_trace_id", t.TraceId))
	}

	if t.SpanId == "" {
		t.SpanId = GenerateSpanId()
		log = log.With(slog.String("new_span_id", t.SpanId))
	}

	if t.Flags == "" {
		t.Flags = "00"
		log = log.With(slog.String("new_flags", t.Flags))
	}

	if t.TraceId == "" || t.SpanId == "" || t.Version == "" || t.Flags == "" {
		log.Warn("missing required fields to build traceparent header: generating new traceparent header")
	}

	return fmt.Sprintf("%s-%s-%s-%s", t.Version, t.TraceId, t.SpanId, t.Flags)
}

// GenerateTraceId generates a Trace Id that is a 128 bits hex string
// in compliance with the W3C Trace Context specification
func GenerateTraceId() string {
	return generateTraceId()
}

// generateTraceId generates a Trace Id that is a 128 bits hex string
// in compliance with the W3C Trace Context specification
func generateTraceId() string {
	bytes := make([]byte, 16) // 16 bytes = 128 bits
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GenerateSpanId generates a Span Id that is a 64 bits hex string
// in compliance with the W3C Trace Context specification
func GenerateSpanId() string {
	return generateSpanId()
}

// generateSpanId generates a Span Id that is a 64 bits hex string
// in compliance with the W3C Trace Context specification
func generateSpanId() string {
	bytes := make([]byte, 8) // 8 bytes = 64 bits
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// ParseTraceparent parses a W3C traceparent header value from an http request into a Telemetry struct
func ParseTraceparent(r *http.Request) (*Traceparent, error) {

	// get the traceparent header
	traceparent := r.Header.Get("traceparent")
	if traceparent == "" {
		return nil, fmt.Errorf("traceparent header is missing")
	}

	// parse the traceparent header
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid traceparent header format: expected 4 parts, got %d", len(parts))
	}

	version := parts[0]
	traceId := parts[1]
	parentId := parts[2]
	flags := parts[3]

	// validate the version number
	if version == "" || len(version) != 2 {
		return nil, fmt.Errorf("missing or invalid version in traceparent header")
	}

	// validate the trace id
	if !validate.IsValidTraceId(traceId) {
		return nil, fmt.Errorf("missing or invalid trace id in traceparent header")
	}

	// validate the parent id
	if !validate.IsValidSpanId(parentId) {
		return nil, fmt.Errorf("missing or invalid span id in traceparent header")
	}

	// validate the flags
	if flags == "" || len(flags) != 2 {
		return nil, fmt.Errorf("missing or invalid flags in traceparent header")
	}

	return &Traceparent{
		Version:      version,
		TraceId:      traceId,
		ParentSpanId: parentId,
		SpanId:       generateSpanId(), // generate a new span id for the current operation
		Flags:        flags,
	}, nil
}

// GenerateTraceParent generates a new Telemetry struct with a new Traceparent
func GenerateTraceParent() *Traceparent {

	traceId := generateTraceId()
	spanId := generateSpanId()

	return &Traceparent{
		Version: TraceparentVersion,
		TraceId: traceId,
		// ParentSpanId is empty because this is the root span of the trace
		SpanId: spanId,
		Flags:  "00", // default to not sampled
	}
}

// ObtainTelemetry collects telemetry from an http request, or generates new telemetry fields if not present or invalid
func ObtainTelemetry(request *http.Request, logger *slog.Logger) *Telemetry {

	// check if logger is nil and set to default if so
	if logger == nil {
		logger = slog.Default()
	}

	// try to parse traceparent header or generate new telemetry if necessary
	tp, err := ParseTraceparent(request)
	if err != nil {
		// generate new telemetry
		tp = GenerateTraceParent()

		// log out with whatever context exists and add the new telemetry fields
		logger.Warn("failed to parse traceparent header: generating new traceparent",
			slog.String("err", err.Error()),
			slog.String("new_trace_id", tp.TraceId),
			slog.String("new_span_id", tp.SpanId),
			slog.String("protocol", validate.SanitizeProtocol(request.Proto)),
			slog.String("method", validate.SanitizeMethod(request.Method)),
			slog.String("url", validate.SanitizePath(request.URL.Path)),
			slog.String("remote_addr", validate.SanitizeIp(getClientIp(request))),
			slog.String("user_agent", validate.SanitizeUserAgent(request.UserAgent())),
			slog.String("host", validate.SanitizeHost(request.Host)),
			slog.String("referrer", request.Referer()),
		)
	}
	return &Telemetry{
		Traceparent: *tp,
		Protocol:    validate.SanitizeProtocol(request.Proto),
		Method:      validate.SanitizeMethod(request.Method),
		Path:        validate.SanitizePath(request.URL.Path),
		RemoteAddr:  validate.SanitizeIp(getClientIp(request)),
		UserAgent:   validate.SanitizeUserAgent(request.UserAgent()),
		Host:        validate.SanitizeHost(request.Host),
		Referrer:    validate.SanitizeReferrer(request.Referer()),
		StartTime:   time.Now(),
	}
}

// getClientIp is a helper function which extracts the client IP address from
// the http request headers or remote address
func getClientIp(r *http.Request) string {

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}

	return r.RemoteAddr
}

// set up context key type to avoid collisions
type telemetryKey string
type telemetryLoggerKey string

const TelemetryKey telemetryKey = "telemetry"
const TelemetryLoggerKey telemetryLoggerKey = "telemetry_logger"

// AddTelemetryToContext adds the Telemetry struct to the request context
func AddTelemetryToContext(request *http.Request, telemetry *Telemetry) *http.Request {

	ctx := context.WithValue(request.Context(), TelemetryKey, telemetry)

	return request.WithContext(ctx)
}

// GetTelemetryFromContext retrieves the Telemetry struct from the request context
func GetTelemetryFromContext(ctx context.Context) (*Telemetry, bool) {

	telemetry, ok := ctx.Value(TelemetryKey).(*Telemetry)

	return telemetry, ok
}
