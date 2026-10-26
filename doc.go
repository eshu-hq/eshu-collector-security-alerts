// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package collector is the SDK adapter for the extracted security-alert
// producer (eshu-hq/eshu#8866). It turns one collector-sdk/v1alpha1 host
// request into one SDK result: it validates the request, resolves the
// activation config (targets plus the host-delivered producer grant) against
// the process environment, runs the securityalert producer, and maps every
// outcome — including a denied grant or an unconfigured scope — to a result
// the host validator accepts. It never mints a grant: production grants are
// issued by core, and without one emission fails closed before any provider
// contact.
package collector
