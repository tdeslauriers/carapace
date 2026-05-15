package telemetry

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/tdeslauriers/carapace/pkg/validate"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// TelemetryKey is the context key used to store telemetry in the context for propagation across service boundaries
type telemetryKey string

const TelemetryKey telemetryKey = "telemetry"

// Telemetry is a struct that holds telemetry data for a request.
// It will include both http header data and grpc metadata for
// telemetry propagation across service boundaries.
type Telemetry struct {
	Traceparent Traceparent `json:"traceparent"` // W3C traceparent header fields

	// HTTP specific fields - these will be empty for grpc requests but are included here for ease of propagation across service boundaries without needing to convert between different telemetry structs
	Protocol   string `json:"protocol,omitempty"`    // refers to the http protocol version
	HttpMethod string `json:"http_method,omitempty"` // refers to the http request method
	Path       string `json:"path,omitempty"`        // refers to the http request path
	Host       string `json:"host,omitempty"`        // refers to the host header of the request
	Referrer   string `json:"referrer,omitempty"`    // refers to the referrer header of the request

	// GRPC specific fields - these will be empty for http requests but are included here for ease of propagation across service boundaries without needing to convert between different telemetry structs
	GrpcMethod    string `json:"grpc_method,omitempty"`    // refers to the grpc method being called
	GrpcAuthority string `json:"grpc_authority,omitempty"` // refers to the :authority pseudo-header in grpc, which is typically the same as the host header in http

	// Common fields
	RemoteAddr string    `json:"remote_addr,omitempty"` // refers to the remote address of the client
	UserAgent  string    `json:"user_agent,omitempty"`  // refers to the user agent of the client
	StartTime  time.Time `json:"start_time"`            // refers to the time the request was received
}

// TelemetryFields returns a slice of slog key value pairs for logging the telemetry fields
func (t *Telemetry) TelemetryFields() []any {

	// these fields should exist for both http and grpc requests
	fields := []any{
		slog.String("trace_id", t.Traceparent.TraceId),
		slog.String("span_id", t.Traceparent.SpanId),
		slog.String("remote_addr", t.RemoteAddr),
		slog.String("user_agent", t.UserAgent),
	}

	// add parent span id if it exists for better traceability in logs
	if t.Traceparent.ParentSpanId != "" {
		fields = append(fields, slog.String("parent_span_id", t.Traceparent.ParentSpanId))
	}

	// add protocol specific fields if they exist
	if t.Protocol != "" {
		fields = append(fields, slog.String("protocol", t.Protocol))
	}

	if t.HttpMethod != "" {
		fields = append(fields, slog.String("http_method", t.HttpMethod))
	}

	if t.Path != "" {
		fields = append(fields, slog.String("path", t.Path))
	}

	if t.Host != "" {
		fields = append(fields, slog.String("host", t.Host))
	}

	if t.Referrer != "" {
		fields = append(fields, slog.String("referrer", t.Referrer))
	}

	if t.GrpcMethod != "" {
		fields = append(fields, slog.String("grpc_method", t.GrpcMethod))
	}

	if t.GrpcAuthority != "" {
		fields = append(fields, slog.String("grpc_authority", t.GrpcAuthority))
	}

	if !t.StartTime.IsZero() {
		fields = append(fields, slog.String("start_time", t.StartTime.Format(time.RFC3339)))
	}

	return fields
}

// ObtainHttpTelemetry collects telemetry from an http request, or generates new telemetry fields if not present or invalid
func ObtainHttpTelemetry(request *http.Request, logger *slog.Logger) *Telemetry {

	if logger == nil {
		logger = slog.Default()
	}

	protocol := validate.SanitizeProtocol(request.Proto)
	method := validate.SanitizeMethod(request.Method)
	path := validate.SanitizePath(request.URL.Path)
	remoteAddr := getClientIp(request)
	userAgent := validate.SanitizeUserAgent(request.UserAgent())
	host := validate.SanitizeHost(request.Host)
	referrer := validate.SanitizeReferrer(request.Referer())

	tp, err := ParseTraceparent(request.Header.Get(TraceparentKey))
	if err != nil {
		tp = NewTraceparent()
		logger.Warn("failed to parse traceparent header: generating new traceparent",
			slog.String("err", err.Error()),
			slog.String("new_trace_id", tp.TraceId),
			slog.String("new_span_id", tp.SpanId),
			slog.String("protocol", protocol),
			slog.String("http_method", method),
			slog.String("path", path),
			slog.String("remote_addr", remoteAddr),
			slog.String("user_agent", userAgent),
			slog.String("host", host),
			slog.String("referrer", referrer),
		)
	}

	return &Telemetry{
		Traceparent: *tp,
		Protocol:    protocol,
		HttpMethod:  method,
		Path:        path,
		RemoteAddr:  remoteAddr,
		UserAgent:   userAgent,
		Host:        host,
		Referrer:    referrer,
		StartTime:   time.Now(),
	}
}

// getClientIp is a helper function which extracts the client IP address from
// the http request headers or remote address
func getClientIp(r *http.Request) string {

	// check x-forwarded-for header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {

		return validate.SanitizeXForwardedFor(xff)
	}

	// check x-real-ip header next
	if xri := r.Header.Get("X-Real-IP"); xri != "" {

		return validate.SanitizeIp(xri)
	}

	// fall back to remote address
	return validate.SanitizeIp(r.RemoteAddr)
}

// ObtainGrpcTelemetry collects telemetry from a grpc context, or generates new telemetry fields if not present or invalid
func ObtainGrpcTelemetry(ctx context.Context, method string, logger *slog.Logger) *Telemetry {

	if logger == nil {
		logger = slog.Default()
	}

	// get metadata from context, if it exists
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		logger.Warn("no metadata in grpc context: generating new traceparent",
			slog.String("grpc_method", method),
		)
		md = metadata.MD{}
	}

	// get grpc specific fields from metadata
	remoteAddr := grpcClientAddr(ctx)
	userAgent := grpcUserAgent(md)
	authority := grpcAuthority(md)

	// try to parse traceparent from metadata or generate new telemetry if necessary
	tp, err := ParseTraceparent(grpcTraceparentValue(md))
	if err != nil {
		tp = NewTraceparent()
		logger.Warn("failed to parse traceparent from grpc metadata: generating new traceparent",
			slog.String("err", err.Error()),
			slog.String("new_trace_id", tp.TraceId),
			slog.String("new_span_id", tp.SpanId),
			slog.String("grpc_method", method),
			slog.String("remote_addr", remoteAddr),
			slog.String("user_agent", userAgent),
			slog.String("authority", authority),
		)
	}

	return &Telemetry{
		Traceparent:   *tp,
		GrpcMethod:    method,
		GrpcAuthority: authority,
		RemoteAddr:    remoteAddr,
		UserAgent:     userAgent,
		StartTime:     time.Now(),
	}
}

// grpcTraceparentValue extracts the raw traceparent string from gRPC incoming metadata,
// returning empty string if the key is absent.
func grpcTraceparentValue(md metadata.MD) string {

	if vals := md.Get(TraceparentKey); len(vals) > 0 {

		return vals[0]
	}

	return ""
}

// grpcClientAddr extracts and sanitizes the client address from the gRPC peer context.
func grpcClientAddr(ctx context.Context) string {

	p, ok := peer.FromContext(ctx)
	if !ok {

		return ""
	}

	return validate.SanitizeIp(p.Addr.String())
}

// grpcUserAgent extracts and sanitizes the user-agent from gRPC incoming metadata.
func grpcUserAgent(md metadata.MD) string {

	if vals := md.Get("user-agent"); len(vals) > 0 {

		return validate.SanitizeUserAgent(vals[0])
	}

	return ""
}

// grpcAuthority extracts and sanitizes the :authority pseudo-header from gRPC incoming metadata.
func grpcAuthority(md metadata.MD) string {

	if vals := md.Get(":authority"); len(vals) > 0 {

		return validate.SanitizeHost(vals[0])
	}

	return ""
}
