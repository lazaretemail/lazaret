// SPDX-License-Identifier: AGPL-3.0-only

package rdap

import (
	"context"

	"strconv"
	"strings"

	"github.com/lazaretemail/lazaret/enrich"
	"github.com/lazaretemail/lazaret/mdm"
	"github.com/lazaretemail/lazaret/mql"
)

// MQL extension functions for address and AS number lookups.
//
// MQL has no such functions, so these are not added to the standard registry. A rule
// using them is an Lazaret rule and will not run on Sublime's engine, and the
// arrangement here makes that impossible to forget: mql.NewRegistry() keeps exactly
// Sublime's surface, the corpus compatibility numbers keep meaning what they say, and a
// deployment opts in by calling Extend.
//
// The namespace is `rdap` rather than something product-branded because it names the
// source of the data, which is the honest description and will still be accurate if the
// project is renamed.

// Capabilities for the extension functions.
//
// These live here rather than in package enrich, which documents Sublime's capability
// surface and should not acquire entries that upstream has never heard of.
const (
	CapIP  enrich.Capability = "rdap.ip"
	CapASN enrich.Capability = "rdap.asn"
)

// Extend registers the extension functions on a registry.
//
// It fails on a strict registry, which is the point: compatibility testing runs against a
// strict one, so an extension cannot silently become part of the surface the corpus is
// measured against.
func Extend(reg *mql.Registry) error {
	funcs := []*mql.Func{
		{
			Name:       "rdap.ip",
			Params:     []mql.Param{{Name: "address"}},
			Return:     mdm.TypeOf(mdm.IPInfo{}),
			Capability: CapIP,
			Doc:        "registration data for an IP address, from the RIR that holds it",
		},
		{
			Name:       "rdap.asn",
			Params:     []mql.Param{{Name: "number"}},
			Return:     mdm.TypeOf(mdm.ASNInfo{}),
			Capability: CapASN,
			Doc:        "registration data for an autonomous system number",
		},
	}
	for _, f := range funcs {
		if err := reg.Register(f); err != nil {
			return err
		}
	}
	return nil
}

// ExtendedRegistry returns the standard function set plus the extensions.
func ExtendedRegistry() (*mql.Registry, error) {
	reg := mql.NewRegistry()
	if err := Extend(reg); err != nil {
		return nil, err
	}
	return reg, nil
}

// Capabilities are the capabilities this client can answer, for registering it with a
// mql.MuxEnricher.
func Capabilities() []enrich.Capability {
	return []enrich.Capability{enrich.CapNetworkWhois, CapIP, CapASN}
}

// enrichIP answers rdap.ip.
func (c *Client) enrichIP(ctx context.Context, args []mql.Value) (mql.Value, error) {
	if len(args) == 0 {
		return mql.NullValue, nil
	}

	// The argument is usually an IP object from the model — `any(headers.ips, ...)`
	// yields one — but a bare string is accepted too.
	addr, ok := args[0].AsString()
	if !ok {
		if inner := args[0].Field("ip"); !inner.IsNull() {
			addr, ok = inner.AsString()
		}
	}
	if !ok || addr == "" {
		return mql.NullValue, nil
	}

	out, err := c.LookupIP(ctx, addr)
	if err != nil {
		return mql.NullValue, &enrich.Unavailable{Capability: CapIP, Reason: "lookup failed", Err: err}
	}
	return mql.FromGo(out), nil
}

// enrichASN answers rdap.asn.
func (c *Client) enrichASN(ctx context.Context, args []mql.Value) (mql.Value, error) {
	if len(args) == 0 {
		return mql.NullValue, nil
	}

	var asn uint64
	if n, ok := args[0].AsInt(); ok && n >= 0 {
		asn = uint64(n)
	} else if s, ok := args[0].AsString(); ok {
		// "AS15169" and "15169" are both written in practice.
		s = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "AS"))
		parsed, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return mql.NullValue, nil
		}
		asn = parsed
	} else {
		return mql.NullValue, nil
	}
	if asn > 4294967295 {
		return mql.NullValue, nil
	}

	out, err := c.LookupASN(ctx, uint32(asn))
	if err != nil {
		return mql.NullValue, &enrich.Unavailable{Capability: CapASN, Reason: "lookup failed", Err: err}
	}
	return mql.FromGo(out), nil
}
