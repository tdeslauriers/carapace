package telemetry

import (
	"context"
	"log/slog"

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

		// check if logger is nil and set to default if so
		if logger == nil {
			logger = slog.Default()
		}

		// get current telemetry from context
		currentTelemetry, ok := ctx.Value(TelemetryKey).(*Telemetry)
		if ok {

			// generate a new span for this outgoing call
			ctx, _ = BuildOutgoingTraceparent(ctx, &currentTelemetry.Traceparent, logger)
		} else {

			// no telemetry in context, generate new one
			// these fields may be used in logging by additional interceptors in the call stack
			regenerated := ObtainGrpcTelemetry(ctx, method, logger)

			logger = logger.With(regenerated.TelemetryFields()...)
			logger.Warn("no telemetry found in context for outgoing grpc call, generating new traceparent")

			// add new telemetry to context
			ctx = context.WithValue(ctx, TelemetryKey, regenerated)

			// add new traceparent to outgoing context metadata
			ctx, _ = BuildOutgoingTraceparent(ctx, &regenerated.Traceparent, logger)
		}

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// BuildOutgoingTraceparent generates a new span for an outgoing grpc call
// and returns both the updated Traceparent and a context with the metadata attached
func BuildOutgoingTraceparent(
	ctx context.Context,
	currentTraceparent *Traceparent,
	logger *slog.Logger,
) (context.Context, *Traceparent) {

	// Create a new traceparent with the current span as the parent
	outgoing := &Traceparent{
		Version:      currentTraceparent.Version,
		TraceId:      currentTraceparent.TraceId,
		ParentSpanId: currentTraceparent.SpanId, // current span becomes parent
		SpanId:       GenerateSpanId(),          // new span for the outgoing call
		Flags:        currentTraceparent.Flags,
	}

	// Add to outgoing context -> grpc metadata
	ctx = metadata.AppendToOutgoingContext(ctx, TraceparentKey, outgoing.BuildTraceparentString(logger))

	return ctx, outgoing
}
