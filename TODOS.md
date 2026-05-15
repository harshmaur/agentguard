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

## TODO 5 — Windows Authenticode signing (EV cert)

**What:** Sign Windows release binaries with Authenticode using an EV cert. Replaces v1.1's "SmartScreen workaround documented" with a signed install that passes SmartScreen reputation silently after enough downloads.

**Why:** Every first-time Windows install in v1.1 hits SmartScreen. Half of CISO reviews will block on this. Buying the cert is the path through that objection.

**Pros:** Removes the trust-thesis killshot on Windows; matches what every commercial security tool ships; reputation builds with downloads.

**Cons:** $300–500/year recurring; hardware token (Yubikey-style) shipped to a physical address; one extra CI secret (cert + PIN); EV cert vendor diligence is its own onboarding flow.

**Context:** v1.1 deferred this per /plan-eng-review issue A5 — founder chose to validate Windows-as-a-market-wedge before paying. Trigger: 3+ design partners ask for signed Windows binaries during v1.1 trial.

**Depends on / blocked by:** v1.1 design partner feedback. Target: v1.2 if asked, otherwise v1.3.

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

