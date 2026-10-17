package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// The check functions return "" for a valid value or a short description of
// the problem. They never repeat the value they check.

// checkHostPort validates host:port with an IPv4 address, an IPv6 address in
// brackets or a DNS name, and a numeric port from 1 to 65535.
func checkHostPort(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		var ae *net.AddrError
		switch {
		case !errors.As(err, &ae):
			return "expected host:port"
		case strings.HasPrefix(ae.Err, "missing port"):
			return "missing port (expected host:port)"
		case strings.HasPrefix(ae.Err, "too many colons"):
			return "expected host:port; IPv6 addresses must be enclosed in brackets, e.g. [2001:db8::10]:9000, and URL schemes are not allowed"
		default:
			return "expected host:port (" + ae.Err + ")"
		}
	}
	if msg := checkPort(port); msg != "" {
		return msg
	}
	return checkHost(host, strings.HasPrefix(addr, "["))
}

func checkPort(port string) string {
	if port == "" {
		return "missing port (expected host:port)"
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return "the port must be a number between 1 and 65535"
	}
	return ""
}

// checkHost validates an IP address or DNS name. bracketed says that the host
// was written in square brackets, which is only valid for IPv6.
func checkHost(host string, bracketed bool) string {
	if host == "" {
		return "the host must not be empty"
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if bracketed && !ip.Is6() {
			return "square brackets are only valid around IPv6 addresses"
		}
		return ""
	}
	if bracketed {
		return "not a valid IPv6 address"
	}
	return checkDNSName(host)
}

// checkDNSName validates a host name: dot separated labels of at most 63
// ASCII letters, digits, '-' and '_' (the latter is common in internal
// names), at most 253 bytes in total, and a trailing dot is allowed.
func checkDNSName(name string) string {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return "not a valid host name"
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "not a valid host name"
		}
		for i := range len(l) {
			ch := l[i]
			switch {
			case ch >= 0x80:
				return "host names must be ASCII; use the punycode (xn--) form of internationalized names"
			case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '-', ch == '_':
			default:
				return "not a valid host name (allowed: letters, digits, '-', '_' and '.')"
			}
		}
	}
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" {
		return "neither a valid IP address nor a valid host name"
	}
	return ""
}

// checkServerName validates a TLS server name: a DNS name or an IP literal
// without port or brackets.
func checkServerName(name string) string {
	if _, err := netip.ParseAddr(name); err == nil {
		return ""
	}
	return checkDNSName(name)
}

// checkWebhookURL validates the webhook URL: only http and https, a host, no
// credentials, no fragment.
func checkWebhookURL(raw string) string {
	if strings.ContainsAny(raw, " \t\r\n") {
		return "must not contain whitespace (percent-encode it)"
	}
	if strings.Contains(raw, "#") {
		return "must not contain a fragment (#...)"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "is not a valid URL (check scheme, host and percent-encoding)"
	}
	switch u.Scheme {
	case "http", "https":
	case "":
		return "must be an absolute URL starting with http:// or https://"
	default:
		return fmt.Sprintf("the scheme must be http or https, got %q", u.Scheme)
	}
	switch {
	case u.Opaque != "":
		return "must be an absolute URL of the form scheme://host/path"
	case u.User != nil:
		return "must not contain credentials; use outputs.webhook.token_env for a bearer token"
	case u.Host == "":
		return "must contain a host"
	case strings.HasSuffix(u.Host, ":"):
		return "the port must not be empty"
	}
	if port := u.Port(); port != "" {
		if msg := checkPort(port); msg != "" {
			return msg
		}
	}
	if msg := checkHost(u.Hostname(), strings.HasPrefix(u.Host, "[")); msg != "" {
		return "invalid host: " + msg
	}
	return ""
}
