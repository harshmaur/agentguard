package parse

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

func parseDependencyManifest(path string, raw []byte) (*DependencyManifest, error) {
	switch filepath.Base(path) {
	case "requirements.txt":
		return parseRequirementsTXT(raw), nil
	case "pyproject.toml":
		return parsePyprojectTOML(raw)
	case "go.mod":
		return parseGoMod(raw), nil
	case "Cargo.toml":
		return parseCargoTOML(raw)
	case "Gemfile":
		return parseGemfile(raw), nil
	case "composer.json":
		return parseComposerJSON(raw)
	default:
		return nil, fmt.Errorf("dependency manifest parse: unsupported file %s", path)
	}
}

func packageJSONDependencyManifest(pkg *PackageJSON, raw []byte) *DependencyManifest {
	if pkg == nil {
		return nil
	}
	m := &DependencyManifest{Ecosystem: "npm"}
	if pkg.Name != "" && pkg.Version != "" {
		m.Dependencies = append(m.Dependencies, Dependency{Name: pkg.Name, Version: pkg.Version, Scope: "package", Line: findDependencyLine(raw, pkg.Name)})
	}
	for _, group := range []struct {
		scope string
		deps  map[string]string
	}{
		{"dependencies", pkg.Dependencies},
		{"devDependencies", pkg.DevDependencies},
		{"optionalDependencies", pkg.OptionalDependencies},
		{"peerDependencies", pkg.PeerDependencies},
	} {
		for name, version := range group.deps {
			m.Dependencies = append(m.Dependencies, Dependency{Name: name, Version: version, Scope: group.scope, Line: findDependencyLine(raw, name)})
		}
	}
	sortDependencies(m.Dependencies)
	return m
}

var requirementLineRE = regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*(?:\[[^\]]+\])?\s*([<>=!~]{1,3})?\s*([^;#\s]+)?`)

func parseRequirementsTXT(raw []byte) *DependencyManifest {
	m := &DependencyManifest{Ecosystem: "pypi"}
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
			continue
		}
		match := requirementLineRE.FindStringSubmatch(trimmed)
		if len(match) == 0 {
			continue
		}
		version := strings.TrimSpace(match[2] + match[3])
		m.Dependencies = append(m.Dependencies, Dependency{Name: normalizePythonName(match[1]), Version: version, Scope: "requirements", Line: i + 1})
	}
	return m
}

func parsePyprojectTOML(raw []byte) (*DependencyManifest, error) {
	var top struct {
		Project struct {
			Dependencies         []string            `toml:"dependencies"`
			OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Dependencies    map[string]any `toml:"dependencies"`
				DevDependencies map[string]any `toml:"dev-dependencies"`
				Group           map[string]struct {
					Dependencies map[string]any `toml:"dependencies"`
				} `toml:"group"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if err := toml.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("pyproject.toml parse: %w", err)
	}
	m := &DependencyManifest{Ecosystem: "pypi"}
	for _, dep := range top.Project.Dependencies {
		name, version := parsePythonRequirement(dep)
		if name != "" {
			m.Dependencies = append(m.Dependencies, Dependency{Name: name, Version: version, Scope: "project.dependencies", Line: findDependencyLine(raw, name)})
		}
	}
	for scope, deps := range top.Project.OptionalDependencies {
		for _, dep := range deps {
			name, version := parsePythonRequirement(dep)
			if name != "" {
				m.Dependencies = append(m.Dependencies, Dependency{Name: name, Version: version, Scope: "project.optional-dependencies." + scope, Line: findDependencyLine(raw, name)})
			}
		}
	}
	appendPoetryDeps := func(scope string, deps map[string]any) {
		for name, value := range deps {
			if strings.EqualFold(name, "python") {
				continue
			}
			m.Dependencies = append(m.Dependencies, Dependency{Name: normalizePythonName(name), Version: poetryVersion(value), Scope: scope, Line: findDependencyLine(raw, name)})
		}
	}
	appendPoetryDeps("tool.poetry.dependencies", top.Tool.Poetry.Dependencies)
	appendPoetryDeps("tool.poetry.dev-dependencies", top.Tool.Poetry.DevDependencies)
	for group, deps := range top.Tool.Poetry.Group {
		appendPoetryDeps("tool.poetry.group."+group+".dependencies", deps.Dependencies)
	}
	sortDependencies(m.Dependencies)
	return m, nil
}

func parseGoMod(raw []byte) *DependencyManifest {
	m := &DependencyManifest{Ecosystem: "go"}
	inRequireBlock := false
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(strings.Split(line, "//")[0])
		if trimmed == "" {
			continue
		}
		if trimmed == "require (" {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && trimmed == ")" {
			inRequireBlock = false
			continue
		}
		if strings.HasPrefix(trimmed, "require ") {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "require "))
		} else if !inRequireBlock {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			m.Dependencies = append(m.Dependencies, Dependency{Name: fields[0], Version: fields[1], Scope: "require", Line: i + 1})
		}
	}
	return m
}

func parseCargoTOML(raw []byte) (*DependencyManifest, error) {
	var top map[string]any
	if err := toml.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("Cargo.toml parse: %w", err)
	}
	m := &DependencyManifest{Ecosystem: "cargo"}
	for _, scope := range []string{"dependencies", "dev-dependencies", "build-dependencies"} {
		if deps, ok := top[scope].(map[string]any); ok {
			for name, value := range deps {
				m.Dependencies = append(m.Dependencies, Dependency{Name: strings.ToLower(name), Version: cargoVersion(value), Scope: scope, Line: findDependencyLine(raw, name)})
			}
		}
	}
	sortDependencies(m.Dependencies)
	return m, nil
}

var gemLineRE = regexp.MustCompile(`^\s*gem\s+["']([^"']+)["']\s*(?:,\s*["']([^"']+)["'])?`)

func parseGemfile(raw []byte) *DependencyManifest {
	m := &DependencyManifest{Ecosystem: "rubygems"}
	for i, line := range strings.Split(string(raw), "\n") {
		match := gemLineRE.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
		version := ""
		if len(match) > 2 {
			version = match[2]
		}
		m.Dependencies = append(m.Dependencies, Dependency{Name: strings.ToLower(match[1]), Version: version, Scope: "gem", Line: i + 1})
	}
	return m
}

func parseComposerJSON(raw []byte) (*DependencyManifest, error) {
	var top struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("composer.json parse: %w", err)
	}
	m := &DependencyManifest{Ecosystem: "packagist"}
	for scope, deps := range map[string]map[string]string{"require": top.Require, "require-dev": top.RequireDev} {
		for name, version := range deps {
			if strings.EqualFold(name, "php") {
				continue
			}
			m.Dependencies = append(m.Dependencies, Dependency{Name: strings.ToLower(name), Version: version, Scope: scope, Line: findDependencyLine(raw, name)})
		}
	}
	sortDependencies(m.Dependencies)
	return m, nil
}

func parsePythonRequirement(s string) (string, string) {
	match := requirementLineRE.FindStringSubmatch(s)
	if len(match) == 0 {
		return "", ""
	}
	return normalizePythonName(match[1]), strings.TrimSpace(match[2] + match[3])
}

func poetryVersion(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case map[string]any:
		for _, key := range []string{"version", "path", "git", "url"} {
			if raw, ok := v[key].(string); ok {
				return raw
			}
		}
	}
	return ""
}

func cargoVersion(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case map[string]any:
		if raw, ok := v["version"].(string); ok {
			return raw
		}
	}
	return ""
}

func normalizePythonName(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

func findDependencyLine(raw []byte, name string) int {
	idx := strings.Index(strings.ToLower(string(raw)), strings.ToLower(name))
	if idx < 0 {
		return 0
	}
	return strings.Count(string(raw[:idx]), "\n") + 1
}

func sortDependencies(deps []Dependency) {
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Line != deps[j].Line {
			return deps[i].Line < deps[j].Line
		}
		return deps[i].Name < deps[j].Name
	})
}
