package grpc

import (
	"context"
	"log/slog"

	"google.golang.org/grpc"
)

// UnaryServerWithTelemetry is a unary server inteceptor that adds telemetry to the incoming context
func UnaryServerWithTelemetry(logger *slog.Logger) grpc.UnaryServerInterceptor {

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {

		// get telemetry form gprc data
		telemetry := ObtainGrpcTelemetry(ctx, info.FullMethod, logger)

		// add telemtry to the call stack context
		ctx = AddGrpcTelemetryToContext(ctx, telemetry)


		return handler(ctx, req)
	}
}
