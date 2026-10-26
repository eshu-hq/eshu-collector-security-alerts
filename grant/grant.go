// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package grant enforces the core-issued producer grant at the emission
// edge of the extracted security-alert collector.
//
// The grant is issued by core under docs/public/reference/
// component-producer-grants.md (eshu-hq/eshu #6709) and installed at cutover
// under the #4047 gate. The draft terms live in
// producer-grant.manifest.DRAFT.yaml in eshu-hq/eshu
// (go/cmd/collector-security-alerts, #8866): producer
// dev.eshu.collector.security-alerts, version 0.1.0, scope security_alert,
// authority mode core_issued_grant, covering security_alert.repository_alert
// at schema 1.0.0 with a 720h maximum lifetime.
//
// STUB: Check verifies grant shape, producer identity, version, scope, kind
// coverage, schema versions, and expiry only. It does NOT verify a core
// issuance signature — no signature scheme exists yet, and issuance itself is
// core-owned. Until core issues and the host delivers a grant, the zero Grant
// is denied and every emission fails closed.
package grant

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// ProducerID is the first-party producer identity from the grant draft.
	ProducerID = "dev.eshu.collector.security-alerts"
	// Version is the draft producer version. It must match
	// metadata.version at admission.
	Version = "0.1.0"
	// Scope must match the manifest-declared collector kind at admission.
	Scope = "security_alert"
	// SchemaVersionV1 is the schema version the covered kind carries.
	SchemaVersionV1 = "1.0.0"
	// MaxLifetime bounds grant duration: no non-expiring grants.
	MaxLifetime = 720 * time.Hour
)

// coveredKinds lists the core-owned fact kinds this producer may emit after
// cutover. Declared evidence stays core/GitOps-owned and is NOT covered
// here: the extracted collector must never emit declared kinds. Unexported
// so no importer can shrink or widen coverage and still pass Check; read a
// copy through CoveredKinds.
var coveredKinds = []string{
	"security_alert.repository_alert",
}

// CoveredKinds returns a copy of the covered kind set. The copy defends the
// fail-closed claim: mutating the returned slice cannot change what Check
// enforces.
func CoveredKinds() []string {
	out := make([]string, len(coveredKinds))
	copy(out, coveredKinds)
	return out
}

// Grant is the host-delivered core issuance a Collect call enforces.
// Until core issues one, the zero value is denied.
type Grant struct {
	// ProducerID must equal ProducerID.
	ProducerID string
	// Version must equal Version.
	Version string
	// Scope must equal Scope.
	Scope string
	// Kinds maps covered fact kinds to their covered schema versions.
	Kinds map[string][]string
	// ExpiresAt bounds the grant lifetime; zero or past denies.
	ExpiresAt time.Time
	// Revoked denies even an otherwise valid grant.
	Revoked bool
}

// Check verifies the grant before any emission. Any mismatch, expiry, or
// revocation fails closed with a non-nil error; callers must not emit.
func Check(g Grant, now time.Time) error {
	if strings.TrimSpace(g.ProducerID) != ProducerID {
		return fmt.Errorf("security alert producer grant denied: producer mismatch")
	}
	if strings.TrimSpace(g.Version) != Version {
		return fmt.Errorf("security alert producer grant denied: version mismatch")
	}
	if strings.TrimSpace(g.Scope) != Scope {
		return fmt.Errorf("security alert producer grant denied: scope mismatch")
	}
	if g.Revoked {
		return errors.New("security alert producer grant denied: grant revoked")
	}
	if g.ExpiresAt.IsZero() || !now.Before(g.ExpiresAt) {
		return errors.New("security alert producer grant denied: grant expired or missing expiry")
	}
	// MaxLifetime bounds grant duration: an expiry past now+MaxLifetime
	// is a non-expiring grant in disguise and is denied. The bound
	// itself stays usable, so UsableGrant(now) still passes Check at now.
	if g.ExpiresAt.After(now.Add(MaxLifetime)) {
		return errors.New("security alert producer grant denied: grant lifetime exceeds maximum")
	}
	for _, kind := range coveredKinds {
		versions, ok := g.Kinds[kind]
		if !ok {
			return fmt.Errorf("security alert producer grant denied: kind %q not covered", kind)
		}
		if !coversSchemaVersion(versions, SchemaVersionV1) {
			return fmt.Errorf("security alert producer grant denied: kind %q lacks schema version %q", kind, SchemaVersionV1)
		}
	}
	return nil
}

func coversSchemaVersion(versions []string, want string) bool {
	for _, version := range versions {
		if strings.TrimSpace(version) == want {
			return true
		}
	}
	return false
}

// UsableGrant builds the minimal valid grant shape for tests. Production
// grants are issued by core, never minted here.
func UsableGrant(now time.Time) Grant {
	return Grant{
		ProducerID: ProducerID,
		Version:    Version,
		Scope:      Scope,
		Kinds:      map[string][]string{"security_alert.repository_alert": {SchemaVersionV1}},
		ExpiresAt:  now.Add(MaxLifetime),
	}
}
