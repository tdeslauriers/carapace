package grpc

import (
	"context"
	"log/slog"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// UnaryClientInterceptorWithTelemetry is a grpc unary client interceptor that propagates telemetry
func UnaryClientWithTelemetry(logger *slog.Logger) grpc.UnaryClientInterceptor {
	
	return func(
		ctx context.Context,
		method string,
		req, reply interface{},
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {

		// get current telemetry from context
		currentTelemetry, ok := GetTelemetryFromContext(ctx)
		if ok {

			// generate a new span for this outgoing call
			var outgoingTraceParent *connect.Traceparent
			ctx, outgoingTraceParent = GetTraceparentForOutgoingCall(ctx, currentTelemetry, logger)

			logger.Info("making outgoing grpc call",
				slog.String("trace_id", outgoingTraceParent.TraceId),
				slog.String("parent_span_id", outgoingTraceParent.ParentSpanId),
				slog.String("span_id", outgoingTraceParent.SpanId),
				slog.String("method", method),
			)
		} else {

			// no telemetry in context, generate new one
			logger.Warn("no telemetry found in context for outgoing grpc call, generating new traceparent",
				slog.String("method", method),
			)
			newTp := connect.GenerateTraceParent()
			ctx = AddTraceparentToOutgoingContext(ctx, newTp, logger)
		}

		// Make the call
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// GetTelemetryFromContext retrieves the GrpcTelemetry struct from the context
func GetTelemetryFromContext(ctx context.Context) (*GrpcTelemetry, bool) {

	telemetry, ok := ctx.Value(connect.TelemetryKey).(*GrpcTelemetry)

	return telemetry, ok
}

// GetTraceparentForOutgoingCall generates a new span for an outgoing grpc call
// and returns both the updated Traceparent and a context with the metadata attached
func GetTraceparentForOutgoingCall(
	ctx context.Context,
	currentTelemetry *GrpcTelemetry,
	logger *slog.Logger,
) (context.Context, *connect.Traceparent) {

	// Create a new traceparent with the current span as the parent
	outgoingTp := &connect.Traceparent{
		Version:      currentTelemetry.Traceparent.Version,
		TraceId:      currentTelemetry.Traceparent.TraceId,
		ParentSpanId: currentTelemetry.Traceparent.SpanId, // current span becomes parent
		SpanId:       connect.GenerateSpanId(),            // new span for the outgoing call
		Flags:        currentTelemetry.Traceparent.Flags,
	}

	// Add to outgoing context
	ctx = AddTraceparentToOutgoingContext(ctx, outgoingTp, logger)

	return ctx, outgoingTp
}

// AddTraceparentToOutgoingContext adds the traceparent to outgoing grpc metadata
// This is used when making grpc calls to other services to propagate the trace
func AddTraceparentToOutgoingContext(
	ctx context.Context,
	tp *connect.Traceparent,
	logger *slog.Logger,
) context.Context {

	traceparentValue := tp.BuildTraceparent(logger)

	return metadata.AppendToOutgoingContext(ctx, "traceparent", traceparentValue)
}
