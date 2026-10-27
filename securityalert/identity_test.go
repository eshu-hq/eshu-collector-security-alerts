package securityalert

import "testing"

// TestNormalizeNameEcosystems covers every normalizeName switch arm,
// including both maven paths and the unsupported-ecosystem error.
func TestNormalizeNameEcosystems(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		ecosystem     Ecosystem
		rawName       string
		namespace     string
		wantName      string
		wantNamespace string
		wantErr       bool
	}{
		{name: "npm scoped", ecosystem: EcosystemNPM, rawName: "@Scope/Name", wantName: "@scope/name", wantNamespace: "scope"},
		{name: "npm bare", ecosystem: EcosystemNPM, rawName: "Lodash", wantName: "lodash"},
		{name: "npm bad scope", ecosystem: EcosystemNPM, rawName: "@/", wantErr: true},
		{name: "pypi separators", ecosystem: EcosystemPyPI, rawName: "My_Package.Name", wantName: "my-package-name"},
		{name: "gomod keeps path", ecosystem: EcosystemGoModule, rawName: "example.com/mod/v2", wantName: "example.com/mod/v2", wantNamespace: "example.com/mod"},
		{name: "maven needs group", ecosystem: EcosystemMaven, rawName: "artifact", wantErr: true},
		{name: "maven with group", ecosystem: EcosystemMaven, rawName: "artifact", namespace: "org.example", wantName: "artifact", wantNamespace: "org.example"},
		{name: "composer split", ecosystem: EcosystemComposer, rawName: "Vendor/Package", wantName: "vendor/package", wantNamespace: "vendor"},
		{name: "composer missing", ecosystem: EcosystemComposer, rawName: "lonely", wantErr: true},
		{name: "nuget lower", ecosystem: EcosystemNuGet, rawName: "Newtonsoft.Json", wantName: "newtonsoft.json"},
		{name: "rubygems lower", ecosystem: EcosystemRubyGems, rawName: "Rails", wantName: "rails"},
		{name: "cargo lower", ecosystem: EcosystemCargo, rawName: "Serde", wantName: "serde"},
		{name: "swift trims git", ecosystem: EcosystemSwift, rawName: "org/Package.git", namespace: "https://github.com/org", wantName: "package", wantNamespace: "github.com/org"},
		{name: "swift blank name", ecosystem: EcosystemSwift, rawName: "/", namespace: "https://github.com/org", wantErr: true},
		{name: "swift no namespace", ecosystem: EcosystemSwift, rawName: "pkg", wantErr: true},
		{name: "hex trims ns", ecosystem: EcosystemHex, rawName: "Phoenix", namespace: "  Org ", wantName: "phoenix", wantNamespace: "org"},
		{name: "generic passthrough", ecosystem: EcosystemGeneric, rawName: "Name", namespace: "ns", wantName: "Name", wantNamespace: "ns"},
		{name: "unknown errors", ecosystem: Ecosystem("brew"), rawName: "wget", wantErr: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotName, gotNS, err := normalizeName(tc.ecosystem, tc.rawName, tc.namespace)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeName(%q, %q, %q) = (%q, %q, nil), want error",
						tc.ecosystem, tc.rawName, tc.namespace, gotName, gotNS)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeName(%q, %q, %q) error = %v", tc.ecosystem, tc.rawName, tc.namespace, err)
			}
			if gotName != tc.wantName || gotNS != tc.wantNamespace {
				t.Fatalf("normalizeName(%q, %q, %q) = (%q, %q), want (%q, %q)",
					tc.ecosystem, tc.rawName, tc.namespace, gotName, gotNS, tc.wantName, tc.wantNamespace)
			}
		})
	}
}

// TestNameHelpers covers goModuleNamespace and allDigits, including the
// version-suffix shape.
func TestNameHelpers(t *testing.T) {
	t.Parallel()

	if got := goModuleNamespace("example.com/mod/v2"); got != "example.com/mod" {
		t.Fatalf("goModuleNamespace(v2 path) = %q, want %q", got, "example.com/mod")
	}
	if got := goModuleNamespace("example.com/mod"); got != "example.com" {
		t.Fatalf("goModuleNamespace(bare) = %q, want %q", got, "example.com")
	}
	if got := goModuleNamespace("single"); got != "" {
		t.Fatalf("goModuleNamespace(slashes) = %q, want empty", got)
	}
	for value, want := range map[string]bool{"199": true, "": false, "v2": false, "2a": false} {
		if got := allDigits(value); got != want {
			t.Fatalf("allDigits(%q) = %v, want %v", value, got, want)
		}
	}
}
