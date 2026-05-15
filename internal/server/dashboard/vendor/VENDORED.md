# Vendored frontend dependencies

These single-file JavaScript libraries are committed verbatim and
served via `//go:embed` from the dashboard package. No Node toolchain
is involved in the audr repo's build. This is the trust-thesis path
the v1.2 design (plan section B2) committed to.

## Current versions

| Library | Version | File | SHA-256 | Size |
|---|---|---|---|---|
| htmx | 2.0.4 | `htmx.min.js` | `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447` | 50917 |
| Alpine.js | 3.14.8 | `alpine.min.js` | `b600e363d99d95444db54acbfb2deffec9ae792aa99a09229bcda078e5b55643` | 44758 |

CodeMirror 6 is deliberately not vendored — it requires a multi-package
npm build to produce a usable bundle, which contradicts the
trust-thesis "no node_modules in the build pipeline" rule. The policy
editor uses a small custom YAML highlighter instead, defined inline
in `policy.js`.

## Provenance

Each library is downloaded from its official npm distribution channel
via the unpkg CDN, which serves the exact files published to the npm
registry. To verify provenance:

```sh
# htmx
curl -fsSL https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js | sha256sum
# Compare against the SHA-256 in the table above.

# Alpine.js
curl -fsSL https://unpkg.com/alpinejs@3.14.8/dist/cdn.min.js | sha256sum
```

You can also independently verify the source on GitHub:

- https://github.com/bigskysoftware/htmx/releases/tag/v2.0.4
- https://github.com/alpinejs/alpine/releases/tag/v3.14.8

## Updating a vendored library

Each library is one file. Update means: download new version, replace
the file, update the table in this README, run the test suite, ship.

```sh
cd internal/server/dashboard/vendor

# Replace with the new version's URL.
curl -fsSL https://unpkg.com/htmx.org@<NEW_VERSION>/dist/htmx.min.js -o htmx.min.js

# Verify the new SHA-256 and update the table above.
sha256sum htmx.min.js
```

Re-run the test suite (`go test -race -count=1 ./internal/server/...`)
to confirm the dashboard still works against the new version. The
dashboard uses the documented stable API of each library — breaking
changes are typically advertised in their changelogs.

## Why not pin the SHA in code

The SHA-256 in this table is documentation, not an enforcement
mechanism. The git history is the actual enforcement: changes to
these files are visible in `git log` and `git diff` like any other
file. Future enhancement: add a `make verify-vendor` target that
checks the on-disk files against the documented hashes. Defer until
a real audit case calls for it.
