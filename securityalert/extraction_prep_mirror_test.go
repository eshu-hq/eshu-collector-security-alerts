// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"encoding/json"
	"strings"
	"testing"
)

// Extraction PREP mirror (eshu-hq/eshu #8866 AC3, extracted path): the
// contracts the extracted collector preserves — admission at schema 1.0.0,
// stable keys, generation binding, and credential stripping — proved against
// the ported constructors, including hostile inputs. Ports the in-tree
// extraction_prep_mirror_test.go case for case, adapted to the SDK Fact
// shape (generation binding via SourceRef.GenerationID, fencing at the
// claim level).
//
// No-Observability-Change: the host wires MetricsRecorder to its own
// signals; this test asserts no recorder is required.

func TestExtractionPrepAdmitsAtV1(t *testing.T) {
	t.Parallel()

	version, ok := SchemaVersionForKind(KindRepositoryAlert)
	if !ok || version != SchemaVersionV1 {
		t.Errorf("SchemaVersionForKind(%q) = %q, %v; want 1.0.0, true", KindRepositoryAlert, version, ok)
	}
	if err := CheckSchemaVersion(KindRepositoryAlert, SchemaVersionV1); err != nil {
		t.Errorf("CheckSchemaVersion(%q, 1.0.0) error = %v, want nil", KindRepositoryAlert, err)
	}

	fact, err := NewRepositoryAlertFact(goldenFixtureContext(), goldenFixtureAlert())
	if err != nil {
		t.Fatalf("NewRepositoryAlertFact() error = %v, want nil", err)
	}
	if fact.SchemaVersion != SchemaVersionV1 {
		t.Errorf("fact SchemaVersion = %q, want 1.0.0", fact.SchemaVersion)
	}
	if fact.Kind != KindRepositoryAlert {
		t.Errorf("fact Kind = %q, want %q", fact.Kind, KindRepositoryAlert)
	}
	if fact.SourceConfidence != "reported" {
		t.Errorf("fact SourceConfidence = %q, want reported", fact.SourceConfidence)
	}
	if err := CheckSchemaVersion(KindRepositoryAlert, "9.9.9"); err == nil {
		t.Error("CheckSchemaVersion(security_alert.repository_alert, 9.9.9) = nil, want rejection")
	}
	if err := CheckSchemaVersion("security_alert.declared_rule", SchemaVersionV1); err == nil {
		t.Error("CheckSchemaVersion(declared kind) = nil, want rejection: the producer must never emit declared kinds")
	}
}

func TestExtractionPrepDeterminism(t *testing.T) {
	t.Parallel()

	first, err := NewRepositoryAlertFact(goldenFixtureContext(), goldenFixtureAlert())
	if err != nil {
		t.Fatalf("NewRepositoryAlertFact() error = %v, want nil", err)
	}
	second, err := NewRepositoryAlertFact(goldenFixtureContext(), goldenFixtureAlert())
	if err != nil {
		t.Fatalf("NewRepositoryAlertFact() error = %v, want nil", err)
	}
	if first.StableKey != second.StableKey {
		t.Errorf("StableKey not deterministic: %q vs %q", first.StableKey, second.StableKey)
	}
	firstRaw, _ := json.Marshal(first.Payload)
	secondRaw, _ := json.Marshal(second.Payload)
	if string(firstRaw) != string(secondRaw) {
		t.Error("payload not deterministic across identical inputs")
	}
}

func TestExtractionPrepURLSanitizationSentinel(t *testing.T) {
	t.Parallel()

	const sentinel = "PREP-SENTINEL-8866"
	ctx := goldenFixtureContext()
	ctx.SourceURI = "https://api.github.com/repos/example-org/example-repo/dependabot/alerts?token=" + sentinel

	hostile := goldenFixtureAlert()
	hostile.HTMLURL = "https://svc:" + sentinel + "@github.com/example-org/example-repo/security/dependabot/42?access_token=" + sentinel + "&plain=1"
	fact, err := NewRepositoryAlertFact(ctx, hostile)
	if err != nil {
		t.Fatalf("NewRepositoryAlertFact(hostile URL) error = %v, want nil", err)
	}
	raw, err := json.Marshal(fact)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), sentinel) {
		t.Errorf("credential sentinel reached persisted fact %q", fact.Kind)
	}
	// Benign parameters survive sanitization; only credentials are stripped.
	if got := fact.Payload["source_url"]; got != "https://github.com/example-org/example-repo/security/dependabot/42?plain=1" {
		t.Errorf("source_url = %v, want benign plain parameter preserved", got)
	}
	if got := fact.SourceRef.URI; got != "https://api.github.com/repos/example-org/example-repo/dependabot/alerts" {
		t.Errorf("SourceRef.URI = %q, want token parameter stripped", got)
	}
	// Positive control: benign provider identity survives so the absence
	// above is meaningful.
	if !strings.Contains(string(raw), "GHSA-abcd-1234") {
		t.Error("positive control: benign advisory identity missing from persisted fact")
	}
}

func TestExtractionPrepHostileInputsFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*EnvelopeContext)
	}{
		{"blank scope", func(c *EnvelopeContext) { c.ScopeID = "  " }},
		{"blank generation", func(c *EnvelopeContext) { c.GenerationID = "" }},
		{"blank collector instance", func(c *EnvelopeContext) { c.CollectorInstanceID = "" }},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := goldenFixtureContext()
			tt.mutate(&ctx)
			if _, err := NewRepositoryAlertFact(ctx, goldenFixtureAlert()); err == nil {
				t.Errorf("NewRepositoryAlertFact() = nil, want fail-closed error for %s", tt.name)
			}
		})
	}
	// A non-positive alert number carries no provider identity: fail closed.
	badNumber := goldenFixtureAlert()
	badNumber.Number = 0
	if _, err := NewRepositoryAlertFact(goldenFixtureContext(), badNumber); err == nil {
		t.Error("NewRepositoryAlertFact(number 0) = nil, want error")
	}
	// An unsupported ecosystem cannot be normalized to a package identity.
	badEcosystem := goldenFixtureAlert()
	badEcosystem.Dependency.Package.Ecosystem = "not-an-ecosystem"
	badEcosystem.SecurityVulnerability.Package.Ecosystem = "not-an-ecosystem"
	if _, err := NewRepositoryAlertFact(goldenFixtureContext(), badEcosystem); err == nil {
		t.Error("NewRepositoryAlertFact(unsupported ecosystem) = nil, want error")
	}
}

func TestExtractionPrepClaimIDNamespace(t *testing.T) {
	t.Parallel()

	first, second := newClaimID(), newClaimID()
	for _, id := range []string{first, second} {
		if !strings.HasPrefix(id, "security-alert-claim-") {
			t.Errorf("claim ID %q missing security-alert-claim- namespace prefix", id)
		}
	}
	if first == second {
		t.Error("consecutive claim IDs identical; claim identity must be unique per acquisition")
	}
}
