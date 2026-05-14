package templates

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/harshmaur/audr/internal/state"
)

// registerEcosystemHandlers installs the language-dependency
// (kind=dep-package) remediation templates. The orchestrator mints
// rule_ids like "osv-npm-package" / "osv-pypi-package" so we
// prefix-match.
//
// Each handler reads the locator's {ecosystem, name, version,
// manifest_path} and produces a fix command appropriate for the
// ecosystem (npm update, pip install --upgrade, cargo update, etc.).
func registerEcosystemHandlers(r *Registry) {
	r.registerPrefix("osv-npm-", ecosystemHandler("npm"))
	r.registerPrefix("osv-pypi-", ecosystemHandler("pypi"))
	r.registerPrefix("osv-pip-", ecosystemHandler("pypi")) // alias
	r.registerPrefix("osv-go-", ecosystemHandler("go"))
	r.registerPrefix("osv-rubygems-", ecosystemHandler("rubygems"))
	r.registerPrefix("osv-gem-", ecosystemHandler("rubygems")) // alias
	r.registerPrefix("osv-crates-io-", ecosystemHandler("cargo"))
	r.registerPrefix("osv-cargo-", ecosystemHandler("cargo")) // alias
	r.registerPrefix("osv-maven-", ecosystemHandler("maven"))
	r.registerPrefix("osv-packagist-", ecosystemHandler("composer"))
	r.registerPrefix("osv-composer-", ecosystemHandler("composer"))
	r.registerPrefix("osv-nuget-", ecosystemHandler("nuget"))
	r.registerPrefix("osv-hex-", ecosystemHandler("hex"))
	r.registerPrefix("osv-pub-", ecosystemHandler("pub"))
	// Catch-all for unrecognized OSV ecosystems — produces a generic
	// "update your dep manifest" prompt rather than 404'ing.
	r.registerPrefix("osv-", ecosystemHandler(""))
}

// ecosystemHandler returns a Handler closure parameterized by
// ecosystem name. Empty ecosystem means "I don't know the package
// manager; emit a generic update prompt and lean on Title for
// context."
func ecosystemHandler(ecosystem string) Handler {
	return func(f state.Finding, loc Locator) (string, string, bool) {
		name := loc.String("name")
		version := loc.String("version")
		manifestPath := loc.String("manifest_path")
		advisoryID := f.MatchRedacted

		if name == "" {
			// Locator didn't have the structured fields — possible if
			// depscan's parser fallbacked to file-kind treatment.
			// Defer to generic fallback.
			return "", "", false
		}

		recipe, cwd := ecosystemUpgradeRecipe(ecosystem, name, manifestPath)

		human := fmt.Sprintf(`Vulnerable %s package: %s %s%s
%s

1. cd %s
2. Run: %s
3. Verify the new version: %s
4. Run your test suite to confirm nothing regressed`, ecosystemLabel(ecosystem), name, version,
			advisoryFooter(advisoryID),
			fixedInLine(f.Description),
			cwd, recipe.upgradeCommand, recipe.verifyCommand)

		ai := fmt.Sprintf(`A vulnerable %s dependency was flagged: %s pinned at %s in %s. %s

Help me upgrade it. Steps:
1. cd to the directory containing the manifest file.
2. Run %q to bump the version.
3. Verify the new pinned version with %q.
4. Run the project's test suite. If anything broke, show me the failures.
Preserve all unrelated parts of the lockfile/manifest. Do not modify any other repository.`,
			ecosystemLabel(ecosystem), name, version, manifestPath,
			fixedInDescription(f.Description, advisoryID),
			recipe.upgradeCommand, recipe.verifyCommand)
		return human, ai, true
	}
}

type upgradeRecipe struct {
	upgradeCommand string
	verifyCommand  string
}

// ecosystemUpgradeRecipe returns the (command-to-run, command-to-verify)
// pair appropriate for the ecosystem. Defaults to a generic message
// when the ecosystem isn't recognized.
func ecosystemUpgradeRecipe(ecosystem, name, manifest string) (upgradeRecipe, string) {
	dir := ""
	if manifest != "" {
		dir = filepath.Dir(manifest)
	}
	if dir == "" {
		dir = "<the directory containing the manifest>"
	}
	switch strings.ToLower(ecosystem) {
	case "npm":
		return upgradeRecipe{
			upgradeCommand: fmt.Sprintf("npm update %s", name),
			verifyCommand:  fmt.Sprintf("npm ls %s", name),
		}, dir
	case "pypi":
		return upgradeRecipe{
			upgradeCommand: fmt.Sprintf("pip install --upgrade %s   # or: uv pip install --upgrade %s", name, name),
			verifyCommand:  fmt.Sprintf("pip show %s | grep ^Version", name),
		}, dir
	case "go":
		return upgradeRecipe{
			upgradeCommand: fmt.Sprintf("go get -u %s && go mod tidy", name),
			verifyCommand:  fmt.Sprintf("go list -m %s", name),
		}, dir
	case "rubygems":
		return upgradeRecipe{
			upgradeCommand: fmt.Sprintf("bundle update %s", name),
			verifyCommand:  fmt.Sprintf("bundle show %s", name),
		}, dir
	case "cargo":
		return upgradeRecipe{
			upgradeCommand: fmt.Sprintf("cargo update -p %s", name),
			verifyCommand:  fmt.Sprintf("cargo tree -p %s | head -3", name),
		}, dir
	case "maven":
		return upgradeRecipe{
			upgradeCommand: fmt.Sprintf("Edit pom.xml: bump <version> for %s. Then run: mvn dependency:tree", name),
			verifyCommand:  fmt.Sprintf("mvn dependency:list -DincludeArtifactIds=%s", basenameMavenArtifact(name)),
		}, dir
	case "composer":
		return upgradeRecipe{
			upgradeCommand: fmt.Sprintf("composer update %s", name),
			verifyCommand:  fmt.Sprintf("composer show %s", name),
		}, dir
	case "nuget":
		return upgradeRecipe{
			upgradeCommand: fmt.Sprintf("dotnet add package %s   # (latest)", name),
			verifyCommand:  fmt.Sprintf("dotnet list package | grep %s", name),
		}, dir
	case "hex":
		return upgradeRecipe{
			upgradeCommand: fmt.Sprintf("mix deps.update %s", name),
			verifyCommand:  fmt.Sprintf("mix deps | grep %s", name),
		}, dir
	case "pub":
		return upgradeRecipe{
			upgradeCommand: fmt.Sprintf("dart pub upgrade %s   # or: flutter pub upgrade %s", name, name),
			verifyCommand:  fmt.Sprintf("dart pub deps | grep %s", name),
		}, dir
	default:
		return upgradeRecipe{
			upgradeCommand: fmt.Sprintf("Bump %s to a non-vulnerable version in the manifest", name),
			verifyCommand:  "Inspect the lockfile or `<your package manager> list` for the new version",
		}, dir
	}
}

func ecosystemLabel(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "go":
		return "Go module"
	case "rubygems":
		return "RubyGems"
	case "cargo":
		return "crates.io"
	case "maven":
		return "Maven"
	case "composer":
		return "Composer"
	case "nuget":
		return "NuGet"
	case "hex":
		return "Hex"
	case "pub":
		return "pub.dev"
	default:
		return "dependency"
	}
}

// basenameMavenArtifact takes a "groupId:artifactId" pair and returns
// the artifactId so the verify command's grep matches. For unrecognized
// shapes, returns the input unchanged.
func basenameMavenArtifact(name string) string {
	if i := strings.LastIndexByte(name, ':'); i >= 0 && i+1 < len(name) {
		return name[i+1:]
	}
	return name
}

// fixedInLine + fixedInDescription extract a fixed-in version hint
// from the finding Description if present. depscan stores it in the
// description as "...Upgrade <name> to <version> or later...".
func fixedInLine(desc string) string {
	if i := strings.Index(desc, "Upgrade "); i >= 0 {
		// Trim to a single sentence so the human output stays brief.
		s := desc[i:]
		if dot := strings.IndexAny(s, ".!"); dot > 0 {
			return s[:dot+1]
		}
		return s
	}
	return desc
}

func fixedInDescription(desc, advisoryID string) string {
	if desc == "" {
		return advisoryID
	}
	if advisoryID == "" || strings.Contains(desc, advisoryID) {
		return desc
	}
	return advisoryID + ": " + desc
}

func advisoryFooter(advisoryID string) string {
	if advisoryID == "" {
		return ""
	}
	return " (" + advisoryID + ")"
}
