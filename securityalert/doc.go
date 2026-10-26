// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package securityalert is the extracted provider security-alert producer
// for eshu-hq/eshu#8866 (collector-security-alerts extraction, part of epic
// #6707). Emission half only: this repository fetches bounded live GitHub
// Dependabot alert metadata and returns a collector-sdk/v1alpha1 Result per
// host claim. Core keeps admission, projection, persistence, claim mutation,
// fencing, and the status read.
//
// The port is byte-faithful to the in-tree census locked in eshu-hq/eshu
// go/cmd/collector-security-alerts/EXTRACTION_PREP.md: the same stable-key
// and fact-ID scheme, the same wire payload, the same URL sanitization, the
// same bounded REST behavior, and the same fail-closed hostile-input
// contract. See README.md for the host-owned seam (durable cursors, shard
// planning, grant issuance, credential minting).
package securityalert
