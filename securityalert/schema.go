// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package securityalert

import (
	"fmt"
	"strings"

	"github.com/eshu-hq/eshu-sdk/factschema"
)

// SchemaVersionV1 is the first repository security-alert fact schema. The
// single emitted kind is at 1.0.0 today (in-tree EXTRACTION_PREP census §4).
//
// SDK GAP (carried): the published factschema module exposes the fact kind
// string (factschema.FactKindSecurityAlertRepositoryAlert) and the contract
// payload encoder, but no per-kind schema-version map and no
// ValidateSchemaVersion admission helper. Until the SDK gains that helper,
// this producer carries the locked version locally and fails closed on
// anything else. Do NOT widen this map without a core-qualified SDK pin.
const SchemaVersionV1 = "1.0.0"

// KindRepositoryAlert identifies one repository-scoped provider security
// alert. It is the only kind this producer may emit.
const KindRepositoryAlert = factschema.FactKindSecurityAlertRepositoryAlert

// SchemaVersionForKind returns the locked schema version for the emitted
// kind. Declared kinds are absent: this producer must never emit them.
func SchemaVersionForKind(kind string) (string, bool) {
	if kind != KindRepositoryAlert {
		return "", false
	}
	return SchemaVersionV1, true
}

// CheckSchemaVersion admits only the locked 1.0.0 version for the emitted
// kind and fails closed on unknown kinds and foreign versions.
func CheckSchemaVersion(kind, version string) error {
	locked, ok := SchemaVersionForKind(kind)
	if !ok {
		return fmt.Errorf("security_alert fact kind %q is not emitted by this producer", kind)
	}
	if strings.TrimSpace(version) != locked {
		return fmt.Errorf(
			"fact kind %q schema_version %q is unsupported; producer supports %q",
			kind,
			strings.TrimSpace(version),
			locked,
		)
	}
	return nil
}
