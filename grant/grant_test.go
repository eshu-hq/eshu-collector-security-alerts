// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package grant

import (
	"testing"
	"time"
)

func TestCheckAcceptsUsableGrant(t *testing.T) {
	t.Parallel()

	if err := Check(UsableGrant(time.Now()), time.Now()); err != nil {
		t.Errorf("Check(UsableGrant()) error = %v, want nil", err)
	}
}

func TestCheckDeniesZeroGrant(t *testing.T) {
	t.Parallel()

	if err := Check(Grant{}, time.Now()); err == nil {
		t.Error("Check(zero Grant) = nil, want fail-closed denial")
	}
}

func TestCheckDeniesRevokedAndExpired(t *testing.T) {
	t.Parallel()

	now := time.Now()
	revoked := UsableGrant(now)
	revoked.Revoked = true
	if err := Check(revoked, now); err == nil {
		t.Error("Check(revoked) = nil, want denial")
	}
	expired := UsableGrant(now.Add(-2 * MaxLifetime))
	if err := Check(expired, now); err == nil {
		t.Error("Check(expired) = nil, want denial")
	}
}

func TestCheckDeniesWrongIdentityAndScope(t *testing.T) {
	t.Parallel()

	now := time.Now()
	for name, mutate := range map[string]func(*Grant){
		"producer": func(g *Grant) { g.ProducerID = "dev.eshu.collector.grafana" },
		"version":  func(g *Grant) { g.Version = "0.2.0" },
		"scope":    func(g *Grant) { g.Scope = "grafana" },
	} {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g := UsableGrant(now)
			mutate(&g)
			if err := Check(g, now); err == nil {
				t.Errorf("Check(%s mismatch) = nil, want denial", name)
			}
		})
	}
}

func TestCheckDeniesUncoveredKindOrVersion(t *testing.T) {
	t.Parallel()

	now := time.Now()
	missingKind := UsableGrant(now)
	missingKind.Kinds = map[string][]string{}
	if err := Check(missingKind, now); err == nil {
		t.Error("Check(missing kind) = nil, want denial")
	}
	wrongVersion := UsableGrant(now)
	wrongVersion.Kinds = map[string][]string{"security_alert.repository_alert": {"9.9.9"}}
	if err := Check(wrongVersion, now); err == nil {
		t.Error("Check(foreign schema version) = nil, want denial")
	}
}

func TestCoveredKindsReturnsCopy(t *testing.T) {
	t.Parallel()

	first := CoveredKinds()
	if len(first) != 1 || first[0] != "security_alert.repository_alert" {
		t.Fatalf("CoveredKinds() = %q, want the single observed kind", first)
	}
	first[0] = "mutated"
	if again := CoveredKinds(); again[0] != "security_alert.repository_alert" {
		t.Error("CoveredKinds() copy is writable into the enforced set")
	}
}
