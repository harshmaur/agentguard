# AgentGuard TODOS

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

**Context:** AgentGuard is a security tool. Telemetry needs an *unusually* careful privacy review — the events it would emit (which MCP servers, which configs, which rules fire) themselves leak information about the customer's environment. Phase 3 design must default to aggregate-only metrics (rule-fire counts) and explicitly avoid any payload that could identify a specific customer's MCP server, secret pattern, or internal repo.

**Depends on / blocked by:** Phase 3 SaaS layer. Privacy review must happen before any byte is sent.
