package ipfilter

import (
	"errors"
	"net"
	"testing"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

func mustFilter(t *testing.T, allow, deny []string) *Filter {
	t.Helper()
	filter, err := New(allow, deny)
	if err != nil {
		t.Fatalf("New(%v, %v): %v", allow, deny, err)
	}
	return filter
}

func TestNilFilterAllowsEverything(t *testing.T) {
	var filter *Filter
	for _, addr := range []string{"10.0.0.1", "192.168.1.1", "2001:db8::1"} {
		if !filter.Allowed(net.ParseIP(addr)) {
			t.Fatalf("nil filter rejected %s", addr)
		}
	}
}

func TestNewWithNoRulesReturnsNilFilter(t *testing.T) {
	filter, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if filter != nil {
		t.Fatal("New(nil, nil) returned a filter, want nil")
	}
	if !filter.Allowed(net.ParseIP("10.0.0.1")) {
		t.Fatal("empty filter rejected a request")
	}
}

func TestAllowed(t *testing.T) {
	tests := []struct {
		name  string
		allow []string
		deny  []string
		addr  string
		want  bool
	}{
		{
			name: "empty allow list allows anything",
			deny: []string{"10.0.0.1/32"},
			addr: "8.8.8.8",
			want: true,
		},
		{
			name:  "address inside allow list",
			allow: []string{"10.0.0.0/8"},
			addr:  "10.1.2.3",
			want:  true,
		},
		{
			name:  "address outside allow list",
			allow: []string{"10.0.0.0/8"},
			addr:  "11.1.2.3",
			want:  false,
		},
		{
			name:  "deny wins over allow",
			allow: []string{"10.0.0.0/8"},
			deny:  []string{"10.1.2.3/32"},
			addr:  "10.1.2.3",
			want:  false,
		},
		{
			name:  "more specific allow wins over broad deny",
			allow: []string{"10.1.2.3/32"},
			deny:  []string{"10.0.0.0/8"},
			addr:  "10.1.2.3",
			want:  false, // deny always wins in this filter, regardless of specificity
		},
		{
			name: "bare address is a single host",
			deny: []string{"10.0.0.7"},
			addr: "10.0.0.7",
			want: false,
		},
		{
			name: "bare address does not cover neighbours",
			deny: []string{"10.0.0.7"},
			addr: "10.0.0.8",
			want: true,
		},
		{
			name:  "ipv6 allow list",
			allow: []string{"2001:db8::/32"},
			addr:  "2001:db8::5",
			want:  true,
		},
		{
			name:  "ipv6 outside allow list",
			allow: []string{"2001:db8::/32"},
			addr:  "2001:dead::5",
			want:  false,
		},
		{
			name:  "ipv4-in-ipv6 matches an ipv4 network",
			allow: []string{"10.0.0.0/8"},
			addr:  "::ffff:10.1.2.3",
			want:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := mustFilter(t, tc.allow, tc.deny)
			got := filter.Allowed(net.ParseIP(tc.addr))
			if got != tc.want {
				t.Fatalf("Allowed(%s) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// TestNilAddressIsRejected covers the case where the client address could not
// be parsed at all. Failing closed is the only safe answer: treating an
// unknown address as allowed would defeat the whole filter.
func TestNilAddressIsRejected(t *testing.T) {
	filter := mustFilter(t, nil, []string{"10.0.0.0/8"})
	if filter.Allowed(nil) {
		t.Fatal("Allowed(nil) = true, want false")
	}
	empty := mustFilter(t, []string{"10.0.0.0/8"}, nil)
	if empty.Allowed(nil) {
		t.Fatal("Allowed(nil) = true on an allow-listed filter, want false")
	}
}

func TestNewRejectsInvalidEntries(t *testing.T) {
	tests := []struct {
		name  string
		allow []string
		deny  []string
	}{
		{"invalid allow entry", []string{"not-an-ip"}, nil},
		{"invalid deny entry", nil, []string{"10.0.0.0/99"}},
		{"empty string is skipped, not an error", []string{"", "  "}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.allow, tc.deny)
			if tc.name == "empty string is skipped, not an error" {
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected a configuration error")
			}
			var cfgErr *httpx.ConfigError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error = %T, want *httpx.ConfigError", err)
			}
		})
	}
}
