// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	sdk "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-collector-security-alerts/securityalert"
)

const (
	// ComponentID is the manifest identity of this collector. Keep it in sync
	// with metadata.id in manifest.yaml.
	ComponentID = "dev.eshu.collector.security_alerts"
	// CollectorKind is the durable collector family name for security-alert
	// facts.
	CollectorKind = securityalert.CollectorKind
	// SourceSystem is the source system name facts carry when the claim does
	// not name one. Hosted claims carry the activation's source system.
	SourceSystem = securityalert.CollectorKind
	// SchemaVersion is the schema version of the emitted
	// security_alert.repository_alert fact.
	SchemaVersion = securityalert.SchemaVersionV1
	// FactKindRepositoryAlert identifies one repository-scoped provider
	// security alert. It is the only kind this producer may emit.
	FactKindRepositoryAlert = securityalert.KindRepositoryAlert
	// ProducerID is the first-party producer identity. Authorization is
	// host-enforced at emission; the satellite carries no grant material.
	ProducerID = "dev.eshu.collector.security_alerts"
)

// FactKinds returns every fact kind this collector may emit, in the order the
// manifest declares them.
func FactKinds() []string {
	return []string{FactKindRepositoryAlert}
}

// Contract returns the SDK fact families this collector may emit.
func Contract() sdk.Contract {
	kinds := FactKinds()
	facts := make([]sdk.FactDeclaration, 0, len(kinds))
	for _, kind := range kinds {
		facts = append(facts, sdk.FactDeclaration{
			Kind:             kind,
			SchemaVersions:   []string{SchemaVersion},
			SourceConfidence: []sdk.SourceConfidence{sdk.SourceConfidenceReported},
		})
	}
	return sdk.Contract{ProtocolVersion: sdk.ProtocolVersionV1Alpha1, Facts: facts}
}
