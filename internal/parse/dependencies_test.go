package parse

import "testing"

func TestDetectFormatDependencyManifest(t *testing.T) {
	for _, path := range []string{
		"/repo/requirements.txt",
		"/repo/pyproject.toml",
		"/repo/go.mod",
		"/repo/Cargo.toml",
		"/repo/Gemfile",
		"/repo/composer.json",
	} {
		if got := DetectFormat(path); got != FormatDependencyManifest {
			t.Fatalf("DetectFormat(%s) = %q, want %q", path, got, FormatDependencyManifest)
		}
	}
}

func TestPackageJSONAlsoBuildsDependencyManifest(t *testing.T) {
	doc := Parse("package.json", []byte(`{
  "name":"agent-app",
  "version":"1.2.3",
  "dependencies":{"@anthropic-ai/sdk":"0.90.0"},
  "devDependencies":{"openclaw":"2026.4.1"}
}`))
	if doc.ParseError != nil {
		t.Fatalf("ParseError = %v", doc.ParseError)
	}
	if doc.PackageJSON == nil {
		t.Fatal("PackageJSON is nil")
	}
	if doc.DependencyManifest == nil || doc.DependencyManifest.Ecosystem != "npm" {
		t.Fatalf("DependencyManifest not populated: %#v", doc.DependencyManifest)
	}
	if !hasDependency(doc.DependencyManifest, "@anthropic-ai/sdk", "0.90.0") || !hasDependency(doc.DependencyManifest, "openclaw", "2026.4.1") {
		t.Fatalf("dependencies not normalized: %#v", doc.DependencyManifest.Dependencies)
	}
}

func TestParseRequirementsTXT(t *testing.T) {
	doc := Parse("requirements.txt", []byte("praisonaiagents==1.6.8\npraisonai>=4.6.34\n"))
	if doc.ParseError != nil {
		t.Fatalf("ParseError = %v", doc.ParseError)
	}
	if doc.DependencyManifest == nil || doc.DependencyManifest.Ecosystem != "pypi" {
		t.Fatalf("DependencyManifest not populated: %#v", doc.DependencyManifest)
	}
	if !hasDependency(doc.DependencyManifest, "praisonaiagents", "==1.6.8") {
		t.Fatalf("requirements not parsed: %#v", doc.DependencyManifest.Dependencies)
	}
}

func TestParsePyprojectTOML(t *testing.T) {
	doc := Parse("pyproject.toml", []byte(`[project]
dependencies = ["praisonaiagents==1.6.8"]
[project.optional-dependencies]
mcp = ["praisonai==4.6.8"]
[tool.poetry.dependencies]
python = "^3.11"
praisonai = "4.6.8"
`))
	if doc.ParseError != nil {
		t.Fatalf("ParseError = %v", doc.ParseError)
	}
	if !hasDependency(doc.DependencyManifest, "praisonaiagents", "==1.6.8") || !hasDependency(doc.DependencyManifest, "praisonai", "4.6.8") {
		t.Fatalf("pyproject deps not parsed: %#v", doc.DependencyManifest.Dependencies)
	}
}

func TestParseGoModCargoGemfileComposer(t *testing.T) {
	cases := []struct {
		path    string
		raw     string
		name    string
		version string
	}{
		{"go.mod", "module x\nrequire github.com/modelcontextprotocol/go-sdk v0.1.0\n", "github.com/modelcontextprotocol/go-sdk", "v0.1.0"},
		{"Cargo.toml", "[dependencies]\nmcp-client = \"0.2.0\"\n", "mcp-client", "0.2.0"},
		{"Gemfile", "gem \"mcp_agent\", \"1.0.0\"\n", "mcp_agent", "1.0.0"},
		{"composer.json", `{"require":{"vendor/mcp-agent":"1.0.0"}}`, "vendor/mcp-agent", "1.0.0"},
	}
	for _, tc := range cases {
		doc := Parse(tc.path, []byte(tc.raw))
		if doc.ParseError != nil {
			t.Fatalf("%s ParseError = %v", tc.path, doc.ParseError)
		}
		if !hasDependency(doc.DependencyManifest, tc.name, tc.version) {
			t.Fatalf("%s dependency not parsed: %#v", tc.path, doc.DependencyManifest.Dependencies)
		}
	}
}

func hasDependency(m *DependencyManifest, name, version string) bool {
	if m == nil {
		return false
	}
	for _, dep := range m.Dependencies {
		if dep.Name == name && dep.Version == version {
			return true
		}
	}
	return false
}
