// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func stringReader(s string) *strings.Reader { return strings.NewReader(s) }

// marshalRequestForTest returns one valid stdio request document.
func marshalRequestForTest() (string, error) {
	raw, err := json.Marshal(Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim: sdk.Claim{
			ComponentID:   ComponentID,
			InstanceID:    "security-alert-primary",
			CollectorKind: CollectorKind,
			SourceSystem:  CollectorKind,
			Scope:         sdk.Scope{ID: "security-alert:github:example-org/example-repo", Kind: "security_alert"},
			SourceRunID:   "run-1",
			GenerationID:  "security-alert:generation-9",
			WorkItemID:    "work-1",
			FencingToken:  "7",
			Attempt:       1,
			Deadline:      time.Now().Add(time.Hour).UTC(),
			ConfigHandle:  "component-config:security-alert",
		},
		Contract: Contract(),
		Config:   map[string]any{},
	})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// TestParseRequestAcceptsMinimalValidRequest proves the documented wire shape
// decodes, including the DisallowUnknownFields-tolerant empty config.
func TestParseRequestAcceptsMinimalValidRequest(t *testing.T) {
	t.Parallel()

	base, err := marshalRequestForTest()
	if err != nil {
		t.Fatal(err)
	}
	request, err := ParseRequest(stringReader(base))
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if request.Claim.InstanceID != "security-alert-primary" {
		t.Fatalf("InstanceID = %q, want security-alert-primary", request.Claim.InstanceID)
	}
}
