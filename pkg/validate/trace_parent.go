package validate

const (
	TraceIdLength = 32 // 128 bits in hex according to W3C Trace Context specification
	SpanIdLength  = 16 // 64 bits in hex according to W3C Trace Context specification
)

// IsValidTraceId checks if a string is a valid W3C Trace Id (32 hex characters).
func IsValidTraceId(traceId string) bool {
	if len(traceId) != TraceIdLength {
		return false
	}
	return isValidHex(traceId)
}

// IsValidSpanId checks if a string is a valid W3C Span Id (16 hex characters).
func IsValidSpanId(spanId string) bool {
	if len(spanId) != SpanIdLength {
		return false
	}
	return isValidHex(spanId)
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
