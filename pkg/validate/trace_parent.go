package validate

import (
	"fmt"
	"strings"
)

const (
	TraceIdLength = 32 // 128 bits in hex according to W3C Trace Context specification
	SpanIdLength  = 16 // 64 bits in hex according to W3C Trace Context specification
)

// ValidateTraceId checks if a string is a valid W3C Trace Id (32 hex characters).
func ValidateTraceId(traceId string) error {
	traceId = strings.TrimSpace(traceId)
	if len(traceId) != TraceIdLength {
		return fmt.Errorf("trace id must be exactly %d hex characters", TraceIdLength)
	}
	if !isValidHex(traceId) {
		return fmt.Errorf("trace id must contain only hexadecimal characters (0-9, a-f, A-F)")
	}
	return nil
}

// ValidateSpanId checks if a string is a valid W3C Span Id (16 hex characters).
func ValidateSpanId(spanId string) error {
	spanId = strings.TrimSpace(spanId)
	if len(spanId) != SpanIdLength {
		return fmt.Errorf("span id must be exactly %d hex characters", SpanIdLength)
	}
	if !isValidHex(spanId) {
		return fmt.Errorf("span id must contain only hexadecimal characters (0-9, a-f, A-F)")
	}
	return nil
}

// IsValidHex checks if a string is a valid hexadecimal string.
func IsValidHex(s string) bool {
	return isValidHex(s)
}

// isValidHex checks if a string is a valid hexadecimal string.
func isValidHex(s string) bool {

	if len(s)%2 != 0 {
		return false
	}

	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
