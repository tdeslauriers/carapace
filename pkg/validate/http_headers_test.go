package validate

import (
	"strings"
	"testing"
)

func TestSanitizeProtocol(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "http1_0",
			input: "HTTP/1.0",
			want:  "HTTP/1.0",
		},
		{
			name:  "http1_1",
			input: "HTTP/1.1",
			want:  "HTTP/1.1",
		},
		{
			name:  "http2_0",
			input: "HTTP/2.0",
			want:  "HTTP/2.0",
		},
		{
			name:  "http3_0",
			input: "HTTP/3.0",
			want:  "HTTP/3.0",
		},
		{
			name:  "unknown_starting_with_H",
			input: "HTTP/9.9",
			want:  "HTTP/9.9",
		},
		{
			name:  "unknown_not_starting_with_H",
			input: "FTP/1.0",
			want:  "unknown/unexpected protocol",
		},
		{
			name:  "empty",
			input: "",
			want:  "unknown/unexpected protocol",
		},
		{
			name:  "too_long_truncated",
			input: strings.Repeat("X", 25),
			want:  "unknown/unexpected protocol",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeProtocol(tt.input)
			if got != tt.want {
				t.Fatalf("SanitizeProtocol(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeMethod(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "GET",
			input: "GET",
			want:  "GET",
		},
		{
			name:  "POST",
			input: "POST",
			want:  "POST",
		},
		{
			name:  "PUT",
			input: "PUT",
			want:  "PUT",
		},
		{
			name:  "PATCH",
			input: "PATCH",
			want:  "PATCH",
		},
		{
			name:  "DELETE",
			input: "DELETE",
			want:  "DELETE",
		},
		{
			name:  "HEAD",
			input: "HEAD",
			want:  "HEAD",
		},
		{
			name:  "OPTIONS",
			input: "OPTIONS",
			want:  "OPTIONS",
		},
		{
			name:  "unknown_passthrough",
			input: "PURGE",
			want:  "PURGE",
		},
		{
			name:  "too_long_truncated",
			input: strings.Repeat("A", 15),
			want:  strings.Repeat("A", 10) + "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeMethod(tt.input)
			if got != tt.want {
				t.Fatalf("SanitizeMethod(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantContain string
		wantExclude string
	}{
		{
			name:        "simple_path",
			input:       "/api/v1/users",
			wantContain: "/api/v1/users",
		},
		{
			name:        "null_bytes_removed",
			input:       "/path\x00with\x00nulls",
			wantExclude: "\x00",
		},
		{
			name:        "newlines_removed",
			input:       "/path\nwith\nnewlines",
			wantExclude: "\n",
		},
		{
			name:        "carriage_returns_removed",
			input:       "/path\rwith\rCR",
			wantExclude: "\r",
		},
		{
			name:        "url_encoded_decoded",
			input:       "/path%20with%20spaces",
			wantContain: "/path with spaces",
		},
		{
			name:        "truncated_if_too_long",
			input:       strings.Repeat("a", MaxPathLength+10),
			wantContain: "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizePath(tt.input)
			if tt.wantContain != "" && !strings.Contains(got, tt.wantContain) {
				t.Fatalf("SanitizePath(%q) = %q, want it to contain %q", tt.input, got, tt.wantContain)
			}
			if tt.wantExclude != "" && strings.Contains(got, tt.wantExclude) {
				t.Fatalf("SanitizePath(%q) = %q, want it NOT to contain %q", tt.input, got, tt.wantExclude)
			}
		})
	}
}

func TestSanitizeIp(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "valid_ipv4",
			input: "192.168.1.1",
			want:  "192.168.1.1",
		},
		{
			name:  "valid_ipv4_with_port",
			input: "192.168.1.1:8080",
			want:  "192.168.1.1",
		},
		{
			name:  "valid_ipv6",
			input: "::1",
			want:  "::1",
		},
		{
			name:  "invalid_ip",
			input: "not-an-ip",
			want:  "invalid",
		},
		{
			name:  "empty",
			input: "",
			want:  "invalid",
		},
		{
			name:  "too_long_truncated_invalid",
			input: strings.Repeat("1", 50),
			want:  "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeIp(tt.input)
			if got != tt.want {
				t.Fatalf("SanitizeIp(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeUserAgent(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantContain string
		wantExclude string
		wantSuffix  string
	}{
		{
			name:        "simple_ua",
			input:       "Mozilla/5.0 (compatible)",
			wantContain: "Mozilla/5.0",
		},
		{
			name:        "control_chars_removed",
			input:       "Agent\x01With\x1fControl",
			wantExclude: "\x01",
		},
		{
			name:        "newline_removed",
			input:       "Agent\nWith\nNewlines",
			wantExclude: "\n",
		},
		{
			name:       "truncated_if_too_long",
			input:      strings.Repeat("A", MaxUserAgentLength+10),
			wantSuffix: "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeUserAgent(tt.input)
			if tt.wantContain != "" && !strings.Contains(got, tt.wantContain) {
				t.Fatalf("SanitizeUserAgent(%q) = %q, want it to contain %q", tt.input, got, tt.wantContain)
			}
			if tt.wantExclude != "" && strings.Contains(got, tt.wantExclude) {
				t.Fatalf("SanitizeUserAgent(%q) = %q, want it NOT to contain %q", tt.input, got, tt.wantExclude)
			}
			if tt.wantSuffix != "" && !strings.HasSuffix(got, tt.wantSuffix) {
				t.Fatalf("SanitizeUserAgent(%q) = %q, want suffix %q", tt.input, got, tt.wantSuffix)
			}
		})
	}
}

func TestSanitizeHost(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple_host",
			input: "example.com",
			want:  "example.com",
		},
		{
			name:  "host_with_port",
			input: "example.com:8080",
			want:  "example.com",
		},
		{
			name:  "ip_host",
			input: "192.168.1.1",
			want:  "192.168.1.1",
		},
		{
			name:  "empty",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeHost(tt.input)
			if got != tt.want {
				t.Fatalf("SanitizeHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeReferrer(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty_passthrough",
			input: "",
			want:  "",
		},
		{
			name:  "full_url_returns_host",
			input: "https://example.com/some/path?q=1",
			want:  "example.com",
		},
		{
			name:  "non_url_returns_empty_host",
			input: "not a url",
			want:  "",
		},
		{
			name:  "truncated_non_url_returns_empty_host",
			input: strings.Repeat("a", MaxReferrerLength+10),
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeReferrer(tt.input)
			if got != tt.want {
				t.Fatalf("SanitizeReferrer(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
