# Audr TODOS

Captured during /plan-eng-review on 2026-04-27. Items are deferred from v1 with explicit rationale, not silently dropped.

---

## TODO 1 — SARIF chunking for large monorepo scans

**What:** When a scan emits more findings than fit in GitHub Code Scanning's SARIF size cap (~10MB compressed, ~25k results), chunk the output into multiple SARIF files OR cap findings emitted with a clear "additional N findings hidden" notice.

**Why:** v1 single-machine scans rarely hit the cap. v2 SaaS fleet aggregation (Phase 3) will routinely produce SARIF that exceeds the cap as it aggregates findings across hundreds of dev machines. If not designed in advance, it becomes a hot fix during the first big customer rollout.

**Pros:**
- Designed in advance, ships cleanly with the SaaS aggregation layer
- Avoids "first big customer rollout" surprise
- Forces a conscious decision on chunking strategy (multiple SARIF files vs result truncation vs both)

**Cons:**
- Premature for v1 (single-machine scans won't approach the limit)
- Requires actually testing against real GitHub limits — those have moved before

**Context:** GitHub Code Scanning SARIF docs: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning. Limits as of 2026: 10MB compressed, 25k results, 1k tags per result. Chunking patterns from existing tools: Snyk and Semgrep both partition by repository when uploading from a multi-repo scan; CodeQL emits one SARIF per database.

**Depends on / blocked by:** Phase 3 SaaS fleet-aggregation work. Not actionable until SaaS layer starts.

---

## TODO 3 — Telemetry beacon design (`--share-anon` flag wiring)

**What:** v1 ships with the `--share-anon` flag wired in CLI surface but no-op (logs the intent locally, sends nothing). Phase 3 (SaaS) defines the actual schema, endpoint, opt-in copy, and privacy review. The flag exists in v1 so users can opt-in early; their preference is captured in local config and honored once the endpoint is live.

**Why:** Designing the telemetry endpoint, schema, opt-in flow, and privacy review before there's a SaaS layer to receive it is premature infrastructure. But removing the `--share-anon` flag entirely and re-adding it later means users who opt-in now don't carry their preference forward. The middle path: ship the flag, persist the preference, no-op until Phase 3.

**Pros:**
- Avoids premature infra in v1
- Captures opt-in preference from day-one users
- Phase 3 telemetry has a real audience (existing users with `--share-anon` set) instead of starting from zero
- Decouples "user wants to share" from "endpoint exists to receive"

**Cons:**
- Slight risk of users thinking telemetry is active when it's no-op (mitigate via clear `--help` text: "Opt-in for v2 telemetry; v1 sends nothing")
- Adds one config field that does nothing in v1

**Context:** Audr is a security tool. Telemetry needs an *unusually* careful privacy review — the events it would emit (which MCP servers, which configs, which rules fire) themselves leak information about the customer's environment. Phase 3 design must default to aggregate-only metrics (rule-fire counts) and explicitly avoid any payload that could identify a specific customer's MCP server, secret pattern, or internal repo.

**Depends on / blocked by:** Phase 3 SaaS layer. Privacy review must happen before any byte is sent.

---

## TODO 4 — BYOD privacy mode (`--byod` flag)

**What:** First-class product axis from the v1 design (P3): two policy modes (BYOD vs Company-Owned) with two output shapes. BYOD: developer sees full findings; company sees aggregate only. Company-Owned: company gets full per-machine telemetry. Deferred from v1.2 because we want 3+ design partners onboarded with the simpler model before locking in the BYOD primitives.

**Why:** Differentiation versus Snyk/Wiz: no incumbent ships BYOD-aware posture management. The two-mode product is a real moat per the v1 office-hours analysis. But designing the privacy split without a real CISO partner sized for BYOD use is premature — we'd build the wrong primitives.

**Pros:** Real moat versus broad-posture tools; named publicly on the roadmap creates outbound conversation hook; pairs cleanly with the v1.2 policy file (BYOD mode = different default policy + different output filter).

**Cons:** Demo needs two scenarios (extra week of demo prep); requires committing to specific privacy primitives that may not match what design partners actually want.

**Context:** P3 in the v1 design doc (`2026-04-27-audr.md`). Implementation hooks: a `mode: byod | company-owned` field in policy.yaml, output formatter that filters per-machine details when mode=byod, daemon flag `--byod` that overrides config.

**Depends on / blocked by:** Three v1.2 design partners onboarded with feedback. Target: v1.3.

---

## TODO 5 — Windows Authenticode signing (closed — won't do)

**Decision (2026-05-16):** explicitly closed. audr is open-source; the $300–500/yr EV-cert recurring spend isn't worth removing a first-run SmartScreen warning that a SHA-256-verifying installer already mitigates. Users can verify the cosign-signed `SHA256SUMS` before "Run anyway" — that's the trust anchor.

Original rationale (kept as historical context):

> Sign Windows release binaries with Authenticode using an EV cert.
> Every first-time Windows install in v1.1 hits SmartScreen.
> ...
> Cons: $300–500/year recurring; hardware token shipped physically; EV cert vendor diligence.

Re-open this TODO if a paying customer demands Authenticode and underwrites the cert cost.

---

## TODO 6 — GitHub Action template (`audr-action`)

**What:** Published GitHub Action (`harshmaur/audr-action@v1`) that runs `audr scan` in CI on PR + push, uploads SARIF to GitHub Code Scanning, comments on PRs with new findings. Listed on the GitHub Marketplace.

**Why:** Today's CI integration is "add `audr scan` as a step in your own workflow." That works but it's not what platform engineers expect from a security scanner. A first-party Action with SARIF upload, PR comments, and Marketplace listing turns audr from "binary you run" into "integration you install."

**Pros:** Marketplace listing = passive discovery channel; PR-comment flow is the established UX (Snyk, Semgrep do this); aligns with SARIF-into-Code-Scanning thesis from v1 P2 refinement.

**Cons:** Adds a separate repo to maintain (`harshmaur/audr-action`); needs its own release pipeline; PR-comment surface is a feature creep magnet.

**Context:** Phase 2 OSS CLI extensions in the v1 design doc. Not v1.1 (platform completeness) or v1.2 (policy lake). Natural fit for v1.3 after policy editing has been validated.

**Depends on / blocked by:** v1.2 policy file shape stable (Action template should embed default policy for new users). Target: v1.3.

---

## TODO 7 — Custom rule definitions (Semgrep-style YAML rules)

**What:** v1.2 ships layered-overrides only (built-ins in Go, user overrides in YAML). v1.3 adds custom rule definitions: users write their own detection rules in YAML with a declarative match spec (path glob + regex/AST match + severity).

**Why:** CISOs ask "can we write our own rules?" in every demo. v1.2's answer is "you can override built-ins but not add new ones." v1.3 closes the gap.

**Pros:** Headline-feature parity with Semgrep/Trivy/Gitleaks; unlocks customer-specific rules ("flag any MCP server we haven't allowlisted"); each customer rule is a sales conversation.

**Cons:** Match engine surface is large (regex vs glob vs structural vs AST); user-written rules are a footgun (bad regex, slow matchers, missed escape); requires a rule-test framework so users can verify their rules fire correctly.

**Context:** Issue 4 of /plan-eng-review 2026-05-15. User chose layered overrides for v1.2; this is the deferred Option B (Semgrep-style declarative rules). Architecturally, the v1.2 layered model is forward-compatible: custom rules become additional entries in the same policy.yaml under a new `custom-rules:` key.

**Depends on / blocked by:** v1.2 ships and design partners use it for ≥1 month. Target: v1.3.

---

## TODO 8 — v1.4 Approach B: AV-feel daily-driver dashboard

**What:** Default-green `/dashboard` route, "Protected for N days" streak primitive, health score 0-100 driven by open chains + criticals, single-banner threat card when a chain fires. The dashboard's default state is comfort (green checkmark, last-verified timestamp). One bold banner only when a chain actually fires.

**Why:** v1.3 ships dedup + roll-up + override snippets (Approach A from the loveable-audr design doc). That earns the founder's attention back. Approach B is what turns "I opened it today" into "I open this every morning." The streak primitive + health score is the first emotional hook audr has had.

**Pros:** Real differentiation vs Snyk/Wiz/SonarQube (none of them feel like AV — they all feel like Jenkins). Forensic mode survives intact at `/audit` for future CISO conversations.

**Cons:** More UX surface area to dogfood. If the "feel" is off by 10% it lands worse than v1.3 alone. A health score is a number people argue with.

**Context:** Approach B in `parallels-main-design-loveable-audr-20260515-171437.md`. Reuses the v1.2 htmx+Alpine stack and the v1.1 toaster. New: `internal/health/`, `internal/streak/`, dashboard templates for the AV view.

**Depends on / blocked by:** v1.3 ships AND ≥2 weeks of dogfood data confirm the dedup pass earns daily attention (the founder voluntarily opens the dashboard 5 days in a row). Target: v1.4.

---

## TODO 9 — v1.5 Approach C: Active quarantine + undo

**What:** When a critical attack chain fires, daemon (opt-in, first-run consent) quarantines the offending config file into `~/.audr/quarantined/<chain-id>/<timestamp>/`. JSONL audit log of every quarantine event. One-click undo from the dashboard. Toast: "audr blocked an exfil chain. View / Undo."

**Why:** The "audr blocked N attacks this week" line is the genuine category-defining wedge — the line no developer-security tool currently ships. Earns the antivirus framing on substance, not just on UI. Closes the loop audr keeps almost-closing: detect → block → undo → green.

**Pros:** Genuinely novel. Earns inbound CISO conversations without a single demo. Active blocking is the unowned wedge from the v1 office-hours, finally made concrete.

**Cons:** Trust bar is much higher than v1.3 — audr is now editing config files, not just reading them. One bad quarantine that breaks a user's IDE = catastrophic trust loss. Defender has 30 years of brand; audr has 6 weeks since v1.0. Some chains (e.g. `claude-third-party-plugin-enabled`) have no single file to quarantine.

**Context:** Approach C in `parallels-main-design-loveable-audr-20260515-171437.md`. Deserves its own office-hours session before scoping — the trust model + first-run consent UX + per-rule consent semantics are all design-partner-shaped decisions.

**Depends on / blocked by:** v1.4 Approach B validated. Own office-hours + plan-eng-review session before any code. Target: v1.5.

---

## TODO 10 — policy.yaml: user-extensible path-class table

**What:** Allow users to extend `internal/triage/authority.go`'s hardcoded path-class table via `~/.audr/policy.yaml`. Map custom path globs to authority labels (YOU / MAINTAINER / UPSTREAM).

**Why:** v1.3 hardcodes ~20 path-class entries based on common dev-machine layouts (Claude Code plugin cache paths, Cursor extension paths, common project roots). Power users with non-standard setups (corporate monorepos, custom vendor cache paths, sandboxed environments) will want to extend this. CISOs onboarded under the v1.4 BYOD work (TODO 4) will almost certainly need it.

**Pros:** Forward-compatible with the v1.2 policy lake. Closes a real gap for the v2 enterprise audience. Modest implementation cost once v1.3 ships.

**Cons:** Premature without enterprise design partners — risk of locking in a YAML schema that doesn't match what design partners need. Three-axis policy (rule overrides + suppressions + path-classes) starts to feel enterprise-shaped if shipped before there's an enterprise asking for it.

**Context:** Surfaced during /plan-eng-review 2026-05-15 (Code Quality section, path-class table decision). v1.3 ships hardcoded for speed; this TODO captures the natural next axis.

**Depends on / blocked by:** TODO 4 (BYOD privacy mode design-partner cycle) OR a v1.3 user explicitly asking for it. Target: v1.4 if a design partner asks, else v2.

