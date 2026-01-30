package validate

import (
	"net"
	"net/url"
	"strings"
)

// for headers validation, since for the most part they are for logging purposes
// I am using a sanitization approach instead of a strict validation approach.
// log failurs should not return an error, but instead log the failure and
// return safe or default values for the header fields.

const (
	MaxPathLength      = 500
	MaxUserAgentLength = 300
	MaxReferrerLength  = 300
)

// SanitizeProtocol checks if the protocol is a known http protocol and
// returns it, otherwise returns a default value
func SanitizeProtocol(protocol string) string {

	// truncate and check for expected format
	if len(protocol) > 20 {
		protocol = protocol[:20] + "..."
	}

	// validate known protocols
	switch protocol {
	case "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0":
		return protocol
	default:
		if len(protocol) > 0 && protocol[0] == 'H' {
			return protocol
		}
		return "unknown/unexpected protocol"
	}
}

// SanitizeMethod checks if the method is a known http method and returns it, otherwise returns a default value
func SanitizeMethod(method string) string {

	// truncate
	if len(method) > 10 {
		method = method[:10] + "..."
	}

	// validate known methods
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		return method
	default:
		return method // log whatever they sent: harmless
	}
}

// SanitizePath checks if the cleans up dangerous characters from the path and returns
// a sanitized version of it.
// path is most dangerous because it could contain anything
func SanitizePath(path string) string {

	// truncate to prevent log spam
	if len(path) > MaxPathLength {
		path = path[:MaxPathLength] + "..."
	}

	// remove null bytes because they can break some log systems
	path = strings.ReplaceAll(path, "\x00", "")

	// remove newlines to mitigate some log injection attacks
	path = strings.ReplaceAll(path, "\n", "")
	path = strings.ReplaceAll(path, "\r", "")

	// decode url to see actual content
	decoded, err := url.QueryUnescape(path)
	if err == nil {
		path = decoded
	}

	return path
}

// should be ip or ip:port
func SanitizeIp(ip string) string {

	// truncate
	if len(ip) > 45 { // max ipv6 length is 39, plus some buffer

		ip = ip[:45]
	}

	// remove port if present
	if host, _, err := net.SplitHostPort(ip); err == nil {

		ip = host
	}

	// validate it's actually an IP
	if net.ParseIP(ip) == nil {

		return "invalid"
	}

	return ip
}

// SanitizeUserAgent attempts to clean up the user agent string by truncating it and removing control characters
// User agent can be very long and contain newlines or other control characters that can
// break logs or cause log injection attacks. This function truncates the user agent to a reasonable length
// and removes any control characters.
func SanitizeUserAgent(userAgent string) string {

	// truncate
	if len(userAgent) > MaxUserAgentLength {
		userAgent = userAgent[:MaxUserAgentLength] + "..."
	}

	// remove control characters and newlines
	userAgent = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 { // control characters
			return -1 // drop them
		}
		return r
	}, userAgent)

	return userAgent
}

// SanitizeHost checks if the host is a valid domain or IP address and returns it, otherwise returns a default value
func SanitizeHost(host string) string {

	// truncate
	if len(host) > 255 { // max domain length
		host = host[:255]
	}

	// remove port for logging (optional)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// remove control characters
	host = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, host)

	return host
}

// SanitizeReferrer attempts to clean up the referrer string by truncating it,
// removing control characters, and only logging the domain.
func SanitizeReferrer(ref string) string {

	if ref == "" {
		return ""
	}

	// truncate
	if len(ref) > MaxReferrerLength {
		ref = ref[:MaxReferrerLength] + "..."
	}

	// remove control characters
	ref = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, ref)

	// only log the domain, not full URL
	if u, err := url.Parse(ref); err == nil {
		return u.Host // Just the domain
	}

	return ref
}
