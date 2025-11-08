package connect

import (
	"net/http"
)

// Response wrapper is used to wrap a http.ResponseWriter to capture status code in logs on defer
type ResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// NewResponseWriter creates a new ResponseWriter via wrapping an existing http.ResponseWriter
func (rw *ResponseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

// Write wraps the underlying ResponseWriter's Write method
func (rw *ResponseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.statusCode = http.StatusOK
		rw.written = true
	}

	return rw.ResponseWriter.Write(b)
}
