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
// Important: a vulnerable dependency reported here is almost always
// a TRANSITIVE dep — something else in the manifest pulled it in.
// The naive "run npm update <leaf>" advice is wrong because:
//
//   - The leaf might not be a direct dependency in package.json;
//     running update on it inserts it directly when it shouldn't be.
//   - The parent that pulled it in may also need updating (or may
//     have already shipped a fix that uses a non-vulnerable version
//     of the transitive).
//   - The parent may NOT have updated yet — then the right move is
//     to override/pin the transitive in the manifest, not upgrade.
//
// So every template here walks the user through:
//
//   1. DIAGNOSE: which top-level dependency pulled this in?
//   2. UPGRADE PARENT: if a newer version of the parent uses a
//      fixed version of the transitive, upgrade THE PARENT.
//   3. FALLBACK: override / pin the transitive if no parent fix
//      exists yet.
//   4. VERIFY: confirm the lockfile reflects the fixed version.
//
// The AI prompt instructs the agent to perform step 1 BEFORE
// proposing any change.
func registerEcosystemHandlers(r *Registry) {
	r.registerPrefix("osv-npm-", ecosystemHandler("npm"))
	r.registerPrefix("osv-pypi-", ecosystemHandler("pypi"))
	r.registerPrefix("osv-pip-", ecosystemHandler("pypi"))
	r.registerPrefix("osv-go-", ecosystemHandler("go"))
	r.registerPrefix("osv-rubygems-", ecosystemHandler("rubygems"))
	r.registerPrefix("osv-gem-", ecosystemHandler("rubygems"))
	r.registerPrefix("osv-crates-io-", ecosystemHandler("cargo"))
	r.registerPrefix("osv-cargo-", ecosystemHandler("cargo"))
	r.registerPrefix("osv-maven-", ecosystemHandler("maven"))
	r.registerPrefix("osv-packagist-", ecosystemHandler("composer"))
	r.registerPrefix("osv-composer-", ecosystemHandler("composer"))
	r.registerPrefix("osv-nuget-", ecosystemHandler("nuget"))
	r.registerPrefix("osv-hex-", ecosystemHandler("hex"))
	r.registerPrefix("osv-pub-", ecosystemHandler("pub"))
	// Catch-all for unrecognized OSV ecosystems — generic advice.
	r.registerPrefix("osv-", ecosystemHandler(""))
}

// ecosystemHandler returns a Handler closure parameterized by
// ecosystem name. Empty ecosystem means "I don't know the package
// manager; emit a generic but still-correct manual flow."
func ecosystemHandler(ecosystem string) Handler {
	return func(f state.Finding, loc Locator) (string, string, bool) {
		name := loc.String("name")
		version := loc.String("version")
		manifestPath := loc.String("manifest_path")
		advisoryID := f.MatchRedacted
		if name == "" {
			// Locator missing structured fields — defer to fallback.
			return "", "", false
		}

		dir := projectDir(manifestPath)
		recipe := buildEcosystemRecipe(ecosystem, name, version, dir)

		human := fmt.Sprintf(`Vulnerable %s package: %s %s%s
%s

This is almost certainly a TRANSITIVE dependency. Do NOT just run
"upgrade %s" — that risks installing a package that wasn't a direct
dependency, or moving it into the wrong place in your manifest. Walk
through the diagnose → fix → verify flow below.

%s`,
			recipe.label, name, version, advisoryFooter(advisoryID),
			fixedInLine(f.Description),
			name,
			recipe.humanFlow,
		)

		ai := fmt.Sprintf(`audr found a vulnerable %s dependency: %s %s%s. %s

DO NOT run a naive "upgrade %s" command. Vulnerable findings against
deps are usually transitive — you have to identify what pulled it in
before you know the right fix. Walk this flow precisely:

%s

Show me the diagnose-step output BEFORE you propose any manifest
edits. If diagnosis shows the leaf is reachable via multiple parents,
list them all. Preserve everything unrelated in the manifest /
lockfile. Do not modify any other repository or run any installs in
the background.`,
			recipe.label, name, version, advisoryFooter(advisoryID),
			fixedInDescription(f.Description, advisoryID),
			name,
			recipe.aiFlow,
		)
		return human, ai, true
	}
}

// ecosystemRecipe holds the per-ecosystem-specific instructions for
// the diagnose → fix-via-parent → fix-via-override → verify flow.
// Each ecosystem's flow is real and tested by its respective package
// manager's documentation; we don't fall back to "edit the manifest
// somehow" generic advice unless ecosystem is empty.
type ecosystemRecipe struct {
	label     string // user-facing ecosystem name in titles
	humanFlow string // multi-step plain-English instructions
	aiFlow    string // step-by-step instructions for the coding agent
}

func buildEcosystemRecipe(ecosystem, name, version, dir string) ecosystemRecipe {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return ecosystemRecipe{
			label: "npm",
			humanFlow: fmt.Sprintf(`1. cd %s

2. DIAGNOSE which top-level dependency pulled %s in:
     npm why %s

   This prints the dependency chain. The line at the TOP of the
   output is what you need to fix — usually one of your direct
   dependencies from package.json.

3. UPGRADE THE PARENT:
     - Check if a newer version of that top-level dep ships a fixed
       transitive: visit its npm page or run "npm view <parent> versions"
     - Upgrade the parent: npm install <parent>@<newer-version>
     - Re-run "npm why %s" to confirm the version moved.

4. FALLBACK — if no parent fix is available yet, override the
   transitive in package.json:

     "overrides": {
       "%s": ">=<fixed-version-from-OSV>"
     }

   Then: npm install

5. VERIFY:
     npm why %s
     npm test`, dir, name, name, name, name, name),
			aiFlow: fmt.Sprintf(`1. cd to %s.
2. Run "npm why %s" and show me the output.
3. Identify the TOP-LEVEL dependency in package.json that pulled %s in.
4. Check npm for a newer version of that parent. Suggest an upgrade
   that doesn't break semver compatibility unless I tell you it's OK.
5. If no parent fix is available, propose an "overrides" entry in
   package.json pinning %s to the fixed version OSV reports.
6. After my approval, apply the change, run npm install, then re-run
   "npm why %s" and "npm test" to confirm.`, dir, name, name, name, name),
		}

	case "pypi":
		return ecosystemRecipe{
			label: "PyPI",
			humanFlow: fmt.Sprintf(`1. cd %s

2. DIAGNOSE which top-level dependency pulled %s in. Use the tool
   your project uses:
     - uv:     uv tree --invert %s
     - poetry: poetry show --tree | grep -B1 %s
     - pip:    pip show %s   (look at "Required-by")
     - pipenv: pipenv graph --reverse

3. UPGRADE THE PARENT, NOT THE LEAF:
   - Find the top-level dep that pulled %s in (it's listed in
     pyproject.toml's [project.dependencies], requirements.txt, or
     poetry's [tool.poetry.dependencies]).
   - Check PyPI for a newer release that ships a non-vulnerable
     transitive.
   - Upgrade in your manifest:
     - uv:     edit pyproject.toml, then "uv lock --upgrade-package <parent> && uv sync"
     - poetry: poetry update <parent>
     - pip:    edit requirements.txt, then pip install -r requirements.txt

4. FALLBACK — if no parent fix exists, pin the transitive directly
   in your manifest:
     - uv:     add to [project.dependencies] in pyproject.toml:
                 "%s>=<fixed-version>"
               then: uv lock && uv sync
     - poetry: in [tool.poetry.dependencies]:
                 %s = ">=<fixed-version>"
               then: poetry lock && poetry install
     - pip:    add to requirements.txt:
                 %s>=<fixed-version>
               then: pip install -r requirements.txt --upgrade

5. VERIFY:
     - uv:     uv tree --invert %s
     - poetry: poetry show %s
     - pip:    pip show %s
   Then run your test suite.`, dir, name, name, name, name, name, name, name, name, name, name, name),
			aiFlow: fmt.Sprintf(`1. cd to %s.
2. Detect which Python package manager this project uses:
   - presence of uv.lock        → uv
   - presence of poetry.lock    → poetry
   - presence of Pipfile.lock   → pipenv
   - else                       → pip/requirements.txt
3. Run the manager-appropriate reverse-deps command for %s and show me
   the parent chain. (uv tree --invert, poetry show --tree, pip show
   Required-by, pipenv graph --reverse.)
4. Identify the TOP-LEVEL dependency that pulled %s in.
5. Check PyPI for a newer version of that parent. Suggest the upgrade
   AGAINST THE PARENT, not the leaf %s.
6. If the parent has no available fix, propose pinning %s directly in
   the manifest. Use the manager-appropriate syntax.
7. After my approval, apply, run the manager's lock + install commands,
   then re-run the reverse-deps query to confirm the new version landed.
8. Critical: %s may not be installed in any active virtualenv — the
   finding came from a lockfile. The fix still belongs in the manifest
   so the next sync produces a clean lockfile.`, dir, name, name, name, name, name),
		}

	case "go":
		return ecosystemRecipe{
			label: "Go module",
			humanFlow: fmt.Sprintf(`1. cd %s

2. DIAGNOSE which module pulled %s in:
     go mod why %s

   The output shows the dependency chain. The first line names a
   top-level requirement in your go.mod.

3. UPGRADE THE PARENT:
     - Check if a newer version of the top-level dep ships a fix:
         go list -m -u <parent>
     - Upgrade:
         go get <parent>@<version>
         go mod tidy

4. FALLBACK — if no parent fix exists, force the fixed version via a
   replace directive in go.mod:

     replace %s => %s <fixed-version>

   Then: go mod tidy

5. VERIFY:
     go mod why %s
     go list -m %s
     go test ./...`, dir, name, name, name, name, name, name),
			aiFlow: fmt.Sprintf(`1. cd to %s.
2. Run "go mod why %s" and show me the parent chain.
3. Identify the TOP-LEVEL require in go.mod that pulled %s in.
4. Run "go list -m -u <parent>" to check for newer versions of the
   parent. Suggest the upgrade.
5. If no parent fix exists, propose a "replace" directive in go.mod
   pinning %s to the version OSV reports as fixed.
6. After my approval, run go mod tidy + go test ./... to confirm.`, dir, name, name, name),
		}

	case "rubygems":
		return ecosystemRecipe{
			label: "RubyGems",
			humanFlow: fmt.Sprintf(`1. cd %s

2. DIAGNOSE which gem pulled %s in:
     bundle viz --version --requirements
     (or open Gemfile.lock and trace the indentation from %s upward)

   The top of the chain is a gem listed in your Gemfile.

3. UPGRADE THE PARENT:
     - Find a newer version of the top-level gem that ships a fix.
     - bundle update <parent-gem>

4. FALLBACK — pin the transitive in Gemfile:

     gem '%s', '>= <fixed-version>'

   Then: bundle install

5. VERIFY:
     bundle show %s
     bundle exec rspec   # or whatever your test command is`, dir, name, name, name, name),
			aiFlow: fmt.Sprintf(`1. cd to %s.
2. Open Gemfile.lock, find %s, walk up the indentation to identify
   the top-level gem that pulled it in.
3. Show me the parent gem name.
4. Check rubygems.org for a newer version with a fixed transitive.
   Suggest "bundle update <parent>".
5. If no parent fix exists, propose pinning %s in Gemfile directly.
6. After my approval, run bundle install and the project's test
   command.`, dir, name, name),
		}

	case "cargo":
		return ecosystemRecipe{
			label: "crates.io",
			humanFlow: fmt.Sprintf(`1. cd %s

2. DIAGNOSE which crate pulled %s in:
     cargo tree --invert -p %s

   The output shows the reverse-dependency chain back to your top-
   level dependencies in Cargo.toml.

3. UPGRADE THE PARENT:
     - Find a newer version of the top-level dep that uses a fixed
       transitive.
     - Edit Cargo.toml's [dependencies] to bump that crate.
     - cargo update -p <parent>

4. FALLBACK — if no parent fix exists, patch the transitive in
   Cargo.toml:

     [patch.crates-io]
     %s = "<fixed-version>"

   Then: cargo update -p %s

5. VERIFY:
     cargo tree --invert -p %s
     cargo test`, dir, name, name, name, name, name),
			aiFlow: fmt.Sprintf(`1. cd to %s.
2. Run "cargo tree --invert -p %s" and show me the output.
3. Identify the top-level crate in Cargo.toml [dependencies] that
   pulled %s in.
4. Check crates.io for a newer version of the parent. Suggest the
   upgrade in Cargo.toml.
5. If no parent fix exists, propose a [patch.crates-io] entry for %s.
6. After my approval, run cargo update and cargo test.`, dir, name, name, name),
		}

	case "maven":
		return ecosystemRecipe{
			label: "Maven",
			humanFlow: fmt.Sprintf(`1. cd %s

2. DIAGNOSE which Maven dep pulled %s in:
     mvn dependency:tree -Dincludes=%s

   The output shows the dependency chain. The topmost entry is a
   direct dependency in pom.xml.

3. UPGRADE THE PARENT:
     - Edit pom.xml: find the top-level <dependency> and bump its
       <version> to a release that ships a fixed transitive.
     - mvn dependency:tree -Dincludes=%s   # confirm new version

4. FALLBACK — pin the transitive via <dependencyManagement> in
   pom.xml:

     <dependencyManagement>
       <dependencies>
         <dependency>
           <groupId>...</groupId>
           <artifactId>%s</artifactId>
           <version>FIXED_VERSION</version>
         </dependency>
       </dependencies>
     </dependencyManagement>

   Then: mvn dependency:tree -Dincludes=%s

5. VERIFY:
     mvn dependency:tree -Dincludes=%s
     mvn test`, dir, name, name, name, basenameMavenArtifact(name), name, name),
			aiFlow: fmt.Sprintf(`1. cd to %s.
2. Run "mvn dependency:tree -Dincludes=%s" and show me the chain.
3. Identify the top-level <dependency> in pom.xml that pulled %s in.
4. Check Maven Central for a newer release of the parent. Suggest
   bumping its <version> in pom.xml.
5. If no parent fix exists, propose a <dependencyManagement> entry
   pinning %s to the fixed version.
6. After my approval, run mvn dependency:tree and mvn test.`, dir, name, name, name),
		}

	case "composer":
		return ecosystemRecipe{
			label: "Composer",
			humanFlow: fmt.Sprintf(`1. cd %s

2. DIAGNOSE which package pulled %s in:
     composer why %s

3. UPGRADE THE PARENT:
     - composer update <parent>

4. FALLBACK — pin the transitive in composer.json:

     "require": {
       "%s": ">=<fixed-version>"
     }

   Then: composer update %s

5. VERIFY:
     composer show %s
     composer test   # if you have a test script defined`, dir, name, name, name, name, name),
			aiFlow: fmt.Sprintf(`1. cd to %s.
2. Run "composer why %s", show me the output.
3. Identify the top-level package in composer.json that pulled %s in.
4. Check Packagist for a newer version. Suggest "composer update
   <parent>".
5. If no parent fix exists, propose adding %s to the "require" block
   directly with a >= fixed-version constraint.
6. After my approval, run composer update and the project's tests.`, dir, name, name, name),
		}

	case "nuget":
		return ecosystemRecipe{
			label: "NuGet",
			humanFlow: fmt.Sprintf(`1. cd %s

2. DIAGNOSE which NuGet package pulled %s in:
     dotnet list package --include-transitive | grep -B2 %s

3. UPGRADE THE PARENT:
     - dotnet add package <parent> --version <newer-version>

4. FALLBACK — pin the transitive directly:
     dotnet add package %s --version <fixed-version>

   This adds it as a direct dependency in your csproj, which then
   forces the version even when other packages pulled it in
   transitively.

5. VERIFY:
     dotnet list package --include-transitive | grep %s
     dotnet test`, dir, name, name, name, name),
			aiFlow: fmt.Sprintf(`1. cd to %s.
2. Run "dotnet list package --include-transitive" and find the parent
   that pulled %s in.
3. Show me the parent package + suggest the upgrade.
4. If no parent fix is available, propose adding %s as a direct
   reference at the fixed version to force it.
5. After my approval, run dotnet add package + dotnet test.`, dir, name, name),
		}

	case "hex":
		return ecosystemRecipe{
			label: "Hex (Elixir)",
			humanFlow: fmt.Sprintf(`1. cd %s

2. DIAGNOSE which dep pulled %s in:
     mix deps.tree | grep -B2 %s

3. UPGRADE THE PARENT:
     - mix deps.update <parent>

4. FALLBACK — override in mix.exs:

     defp deps do
       [
         {:%s, ">= <fixed-version>", override: true},
         # ... other deps
       ]
     end

   Then: mix deps.get

5. VERIFY:
     mix deps | grep %s
     mix test`, dir, name, name, name, name),
			aiFlow: fmt.Sprintf(`1. cd to %s.
2. Run "mix deps.tree" and find the parent of %s.
3. Suggest "mix deps.update <parent>" first.
4. If parent isn't patched, propose an "override: true" entry in
   mix.exs deps/0 pinning %s to the fixed version.
5. After my approval, run mix deps.get + mix test.`, dir, name, name),
		}

	case "pub":
		return ecosystemRecipe{
			label: "pub.dev",
			humanFlow: fmt.Sprintf(`1. cd %s

2. DIAGNOSE which dep pulled %s in:
     dart pub deps --no-dev | grep -B2 %s
     (or: flutter pub deps for Flutter projects)

3. UPGRADE THE PARENT:
     - dart pub upgrade <parent>
     (or: flutter pub upgrade <parent>)

4. FALLBACK — override in pubspec.yaml:

     dependency_overrides:
       %s: '>=<fixed-version>'

   Then: dart pub get  (or flutter pub get)

5. VERIFY:
     dart pub deps
     dart test  (or: flutter test)`, dir, name, name, name),
			aiFlow: fmt.Sprintf(`1. cd to %s.
2. Detect dart vs flutter (look for flutter section in pubspec.yaml).
3. Run "dart pub deps" / "flutter pub deps" and find the parent of %s.
4. Suggest "dart pub upgrade <parent>".
5. If parent isn't patched, propose a "dependency_overrides" entry
   pinning %s.
6. After my approval, run pub get and the project's tests.`, dir, name, name),
		}

	default:
		// Unknown ecosystem — generic but still diagnosis-first.
		return ecosystemRecipe{
			label: "dependency",
			humanFlow: fmt.Sprintf(`1. cd %s

2. DIAGNOSE which top-level dependency pulled %s in. Your package
   manager will have an "inverse dependency" command:
     - npm: npm why <pkg>
     - python (uv/poetry/pip): uv tree --invert / poetry show --tree / pip show
     - go: go mod why <pkg>
     - rust: cargo tree --invert -p <pkg>
     - maven: mvn dependency:tree -Dincludes=<pkg>
     - etc.

3. UPGRADE THE PARENT, not the vulnerable leaf. Bump the top-level
   dep in your manifest to a release that ships a fixed transitive.

4. FALLBACK — if no parent fix exists yet, pin or override %s
   directly in your manifest at the fixed version OSV reports.

5. VERIFY with the same reverse-deps command from step 2 plus your
   test suite.

Avoid running "upgrade %s" naively: it can install the leaf as a
direct dep where it shouldn't be, or do nothing useful if your
manifest doesn't reference it directly.`, dir, name, name, name),
			aiFlow: fmt.Sprintf(`1. cd to %s.
2. Detect the package manager from manifest files (package.json,
   pyproject.toml, go.mod, Cargo.toml, etc.) and use its reverse-
   dependency command to identify what pulled %s in. Show me the
   chain.
3. Identify the TOP-LEVEL parent.
4. Suggest upgrading the parent; if no parent fix exists, propose
   pinning or overriding %s directly in the manifest at the OSV-
   reported fixed version.
5. After my approval, run the manager's install + test commands.`, dir, name, name),
		}
	}
}

// projectDir returns the directory containing the manifest, with a
// sensible placeholder when the locator doesn't have one.
func projectDir(manifest string) string {
	if manifest == "" {
		return "<the directory containing the manifest>"
	}
	d := filepath.Dir(manifest)
	if d == "" || d == "." {
		return manifest
	}
	return d
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
// from the finding Description if present.
func fixedInLine(desc string) string {
	if i := strings.Index(desc, "Upgrade "); i >= 0 {
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
