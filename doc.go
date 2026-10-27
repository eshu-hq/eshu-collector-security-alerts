// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package collector is the SDK adapter for the extracted security-alert
// producer (eshu-hq/eshu#8866). It turns one collector-sdk/v1alpha1 host
// request into one SDK result: it validates the request, resolves the
// activation config (targets plus the shared host-level limits stanza)
// against the process environment, runs the securityalert producer, and maps
// every outcome — including a bad activation or a target outside the claim scope — to a
// result the host validator accepts. Authorization is host-enforced at
// emission; the satellite carries no authorization material.
package collector
