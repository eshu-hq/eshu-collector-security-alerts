// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"net/url"
	"strings"
)

// sanitizeURL strips credentials from a source or provider URL before it
// reaches a persisted envelope: userinfo is removed, sensitive query keys
// are deleted, and a value that cannot be taken apart (or that carries
// userinfo without a hierarchical authority) drops to "". Benign parameters
// survive. Ported from the in-tree envelope sanitizer; the golden test pins
// its behavior.
func sanitizeURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		// Fail closed: nothing can prove a string credential-free when it
		// cannot be taken apart.
		return ""
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		// Not hierarchical, so User can be nil with a credential in plain
		// sight (`svc:SECRET@host/x` keeps it in Opaque). Ask net/url about
		// the authority spelling and drop the value when it carries userinfo.
		if carriesUserinfo(trimmed) {
			return ""
		}
		return trimmed
	}
	parsed.User = nil
	query := parsed.Query()
	for key := range query {
		if isSensitiveQueryKey(key) {
			query.Del(key)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func isSensitiveQueryKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "access_token", "api_key", "apikey", "auth", "authorization", "jwt",
		"key", "password", "passwd", "secret", "sig", "signature", "token",
		"x-amz-credential", "x-amz-security-token", "x-amz-signature":
		return true
	default:
		return false
	}
}

// carriesUserinfo reports whether value embeds a credential in userinfo
// position under any reading net/url accepts: the direct parse, or the
// authority re-parse when an opaque body is shaped like an authority. An
// unparseable value reports true — nothing can prove a string
// credential-free when it cannot be taken apart — so a fail-closed caller
// drops or refuses it.
func carriesUserinfo(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil {
		return true
	}
	if parsed.User != nil {
		return true
	}
	if !opaqueHasAuthority(parsed.Opaque) {
		return false
	}
	authority, err := url.Parse("//" + value)
	if err != nil {
		return true
	}
	return authority.User != nil
}

// opaqueHasAuthority reports whether an opaque URL body is shaped like an
// authority (an "@" ahead of the first "/"), the only shape for which the
// re-parse can reveal userinfo. Values like `mcp:tool/name` or purls such as
// `pkg:npm/lodash@4.17.21` carry no userinfo under any reading.
func opaqueHasAuthority(opaque string) bool {
	if opaque == "" {
		return false
	}
	authority := opaque
	if slash := strings.IndexByte(opaque, '/'); slash >= 0 {
		authority = opaque[:slash]
	}
	return strings.IndexByte(authority, '@') >= 0
}
