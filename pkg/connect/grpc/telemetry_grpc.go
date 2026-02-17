package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// GrpcTelemetry contains grpc request metadata telemetry fields for logging purposes
type GrpcTelemetry struct {
	Traceparent connect.Traceparent `json:"traceparent,omitempty"` // W3C traceparent header fields
	Method      string              `json:"method,omitempty"`      // grpc method being called
	RemoteAddr  string              `json:"remote_addr,omitempty"` // remote address of the client
	UserAgent   string              `json:"user_agent,omitempty"`  // user agent of the client
	Authority   string              `json:"authority,omitempty"`   // :authority pseudo-header
	StartTime   time.Time           `json:"start_time,omitempty"`  // time the request was received
}

// NewGrpcTelemetry creates a new GrpcTelemetry struct from a grpc context,
// AND also generates a new Traceparent to send to service calls.
// NOTE: this function is intended for gateway services that do not expect a
// traceparent header from the client. Internal services should use ObtainGrpcTelemetry instead,
// which will attempt to parse the traceparent metadata and generate a new one if it is not present or invalid.
func NewGrpcTelemetry(ctx context.Context, method string, logger *slog.Logger) *GrpcTelemetry {

	// check if logger is nil and set to default if so
	if logger == nil {
		logger = slog.Default()
	}

	traceParent := connect.GenerateTraceParent()
	remoteAddr := getGrpcClientAddr(ctx)
	userAgent := getGrpcUserAgent(ctx)
	authority := getGrpcAuthority(ctx)
	startTime := time.Now().UTC()

	logger.Info("creating new grpc telemetry for request",
		slog.String("trace_id", traceParent.TraceId),
		slog.String("span_id", traceParent.SpanId),
		slog.String("method", method),
		slog.String("remote_addr", remoteAddr),
		slog.String("user_agent", userAgent),
		slog.String("authority", authority),
		slog.String("start_time", startTime.Format(time.RFC3339)),
	)

	return &GrpcTelemetry{
		Traceparent: *traceParent,
		Method:      method,
		RemoteAddr:  remoteAddr,
		UserAgent:   userAgent,
		Authority:   authority,
		StartTime:   startTime,
	}
}

// ObtainGrpcTelemetry collects telemetry from a grpc context, or generates new telemetry fields if not present or invalid
func ObtainGrpcTelemetry(ctx context.Context, method string, logger *slog.Logger) *GrpcTelemetry {

	// check if logger is nil and set to default if so
	if logger == nil {
		logger = slog.Default()
	}

	// try to parse traceparent from metadata or generate new telemetry if necessary
	tp, err := ParseGrpcTraceparent(ctx)
	if err != nil {

		// generate new telemetry
		tp = connect.GenerateTraceParent()

		// log out with whatever context exists and add the new telemetry fields
		logger.Warn("failed to parse traceparent from grpc metadata: generating new traceparent",
			slog.String("err", err.Error()),
			slog.String("new_trace_id", tp.TraceId),
			slog.String("new_span_id", tp.SpanId),
			slog.String("method", method),
			slog.String("remote_addr", getGrpcClientAddr(ctx)),
			slog.String("user_agent", getGrpcUserAgent(ctx)),
			slog.String("authority", getGrpcAuthority(ctx)),
		)
	}

	return &GrpcTelemetry{
		Traceparent: *tp,
		Method:      method,
		RemoteAddr:  getGrpcClientAddr(ctx),
		UserAgent:   getGrpcUserAgent(ctx),
		Authority:   getGrpcAuthority(ctx),
		StartTime:   time.Now(),
	}
}

// ParseGrpcTraceparent parses a W3C traceparent from grpc metadata into a Traceparent struct
func ParseGrpcTraceparent(ctx context.Context) (*connect.Traceparent, error) {

	// get metadata from context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no metadata in context")
	}

	// get the traceparent from metadata
	traceparents := md.Get("traceparent")
	if len(traceparents) == 0 {
		return nil, fmt.Errorf("traceparent metadata is missing")
	}

	traceparent := traceparents[0]
	if traceparent == "" {
		return nil, fmt.Errorf("traceparent metadata is empty")
	}

	// parse the traceparent
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid traceparent format: expected 4 parts, got %d", len(parts))
	}

	version := parts[0]
	traceId := parts[1]
	parentId := parts[2]
	flags := parts[3]

	// validate the version number
	if version == "" || len(version) != 2 {
		return nil, fmt.Errorf("missing or invalid version in traceparent")
	}

	// validate the trace id
	if !validate.IsValidTraceId(traceId) {
		return nil, fmt.Errorf("missing or invalid trace id in traceparent")
	}

	// validate the parent id
	if !validate.IsValidSpanId(parentId) {
		return nil, fmt.Errorf("missing or invalid span id in traceparent")
	}

	// validate the flags
	if flags == "" || len(flags) != 2 {
		return nil, fmt.Errorf("missing or invalid flags in traceparent")
	}

	return &connect.Traceparent{
		Version:      version,
		TraceId:      traceId,
		ParentSpanId: parentId,
		SpanId:       connect.GenerateSpanId(), // generate a new span id for the current operation
		Flags:        flags,
	}, nil
}

// TelemetryFields adds telemetry fields to the logger from the GrpcTelemetry struct
func (t *GrpcTelemetry) TelemetryFields() []any {

	fields := []any{
		slog.String("trace_id", t.Traceparent.TraceId),
		slog.String("span_id", t.Traceparent.SpanId),
	}

	// add parent span id if it exists
	if t.Traceparent.ParentSpanId != "" {
		fields = append(fields, slog.String("parent_span_id", t.Traceparent.ParentSpanId))
	}

	// add grpc call fields if they exist
	if t.Method != "" {
		fields = append(fields, slog.String("method", t.Method))
	}

	// add remote address field if it exists
	if t.RemoteAddr != "" {
		fields = append(fields, slog.String("remote_addr", t.RemoteAddr))
	}

	// add user agent field if it exists
	if t.UserAgent != "" {
		fields = append(fields, slog.String("user_agent", t.UserAgent))
	}

	// add authority if it exists
	if t.Authority != "" {
		fields = append(fields, slog.String("authority", t.Authority))
	}

	return fields
}

// getGrpcClientAddr is a helper function that extracts the client address from the grpc context
func getGrpcClientAddr(ctx context.Context) string {

	p, ok := peer.FromContext(ctx)
	if !ok {

		return ""
	}

	return validate.SanitizeIp(p.Addr.String())
}

// getGrpcUserAgent is a helper function that extracts the user agent from the grpc metadata
func getGrpcUserAgent(ctx context.Context) string {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {

		return ""
	}

	userAgents := md.Get("user-agent")
	if len(userAgents) > 0 {

		return validate.SanitizeUserAgent(userAgents[0])
	}

	return ""
}

// getGrpcAuthority is a helper function that extracts the :authority pseudo-header from the grpc metadata
func getGrpcAuthority(ctx context.Context) string {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {

		return ""
	}

	authorities := md.Get(":authority")
	if len(authorities) > 0 {

		return validate.SanitizeHost(authorities[0])
	}

	return ""
}

// AddGrpcTelemetryToContext adds the GrpcTelemetry struct to the context
func AddGrpcTelemetryToContext(ctx context.Context, telemetry *GrpcTelemetry) context.Context {

	return context.WithValue(ctx, connect.TelemetryKey, telemetry)
}
