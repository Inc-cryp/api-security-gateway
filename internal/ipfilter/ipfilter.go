// Package ipfilter decides whether a client address may reach a route.
package ipfilter

import (
	"fmt"
	"net"
	"strings"

	"github.com/Inc-cryp/api-security-gateway/internal/httpx"
)

// Filter decides whether a client address may proceed.
//
// A nil *Filter allows everything, which is what a route with no IP rules
// gets. That is deliberate: absence of configuration must not silently block
// traffic, but it also must never be confused with "deny all".
type Filter struct {
	allow []*net.IPNet
	deny  []*net.IPNet
}

// New compiles the allow and deny lists. A bare address with no prefix length
// is treated as a single-host network, so "10.0.0.7" behaves as "10.0.0.7/32".
// New(nil, nil) returns a nil *Filter that allows everything.
func New(allow, deny []string) (*Filter, error) {
	if len(allow) == 0 && len(deny) == 0 {
		return nil, nil
	}
	allowNets, err := compile(allow, "allowed_ips")
	if err != nil {
		return nil, err
	}
	denyNets, err := compile(deny, "denied_ips")
	if err != nil {
		return nil, err
	}
	return &Filter{allow: allowNets, deny: denyNets}, nil
}

func compile(entries []string, field string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(entries))
	for i, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		cidr := entry
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, &httpx.ConfigError{Field: fmt.Sprintf("%s[%d]", field, i), Value: entry, Err: fmt.Errorf("not an IP address or CIDR")}
			}
			if v4 := ip.To4(); v4 != nil {
				cidr = v4.String() + "/32"
			} else {
				cidr = ip.String() + "/128"
			}
		}
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, &httpx.ConfigError{Field: fmt.Sprintf("%s[%d]", field, i), Value: entry, Err: err}
		}
		out = append(out, block)
	}
	return out, nil
}

// Allowed reports whether ip passes the filter.
//
// Deny always wins: an address that matches both lists is rejected. The
// longest matching prefix within a list decides, so a specific deny entry
// overrides a broad allow entry and vice versa. When the allow list is
// non-empty, an address that matches nothing is rejected.
func (f *Filter) Allowed(ip net.IP) bool {
	if f == nil {
		return true
	}
	if ip == nil {
		return false
	}
	normalized := normalize(ip)
	if normalized == nil {
		return false
	}
	if longestMatch(f.deny, normalized) >= 0 {
		return false
	}
	if len(f.allow) == 0 {
		return true
	}
	return longestMatch(f.allow, normalized) >= 0
}

// longestMatch returns the prefix length of the most specific network that
// contains ip, or -1 when none does.
func longestMatch(networks []*net.IPNet, ip net.IP) int {
	best := -1
	for _, block := range networks {
		if !block.Contains(ip) {
			continue
		}
		if ones, _ := block.Mask.Size(); ones > best {
			best = ones
		}
	}
	return best
}

// normalize folds an IPv4 address into its 4-byte form so that a v4 address
// written as a v4-in-v6 literal still matches a v4 network.
func normalize(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	if v6 := ip.To16(); v6 != nil {
		return v6
	}
	return nil
}
