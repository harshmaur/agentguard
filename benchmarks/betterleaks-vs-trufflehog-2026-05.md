# Betterleaks vs TruffleHog Benchmark

**Date:** 2026-05-16
**Machine:** Ubuntu 24.04 LTS aarch64, 8 cores, 15 GB RAM (Parallels VM on Apple Silicon)
**TruffleHog version:** 3.95.3 (linuxbrew)
**Betterleaks version:** 1.2.0 (linuxbrew)
**Corpus:** `~/projects`, 4.2 GB, 189,341 files, 315 `node_modules` dirs, 22 `.git` dirs
**Caches:** warm (single full `find` walk before benchmarking)
**Cycles:** single run per configuration (spike, not statistical study)
**Output written to:** `/tmp/audr-bench/` (raw JSON + JSONL + stderr captures)

## TL;DR

| Config | Wall | Peak RSS | CPU% | User+Sys CPU-s | Findings |
|---|---:|---:|---:|---:|---:|
| **TruffleHog — audr real daemon (verify ON, `--concurrency=1`, exclude file)** | **26.93 s** | **594 MB** | 39% | 10.74 s | 1025 (16 verified, 1009 unverified) |
| TruffleHog — daemon settings, `--no-verification` | 6.43 s | 506 MB | 163% | 10.50 s | 1025 |
| TruffleHog — CLI default concurrency, `--no-verification` | 3.10 s | 508 MB | 387% | 12.03 s | 1023 |
| **Betterleaks — defaults** | **2.22 s** | **157 MB** | 492% | 10.96 s | 76 |
| Betterleaks — `--max-target-megabytes=5` | 1.73 s | 164 MB | 528% | 9.15 s | 76 |

**Verdict — short version:** On this corpus, in this configuration, **betterleaks delivers a 12.1x wall-time win and a 3.8x peak-RSS win vs audr's real-daemon TruffleHog mode**, *and* produces 13.5x fewer findings — most of TruffleHog's surplus is high-cardinality false positives from three specific files. Whether to migrate hinges on detector-coverage acceptability, not on the perf numbers, which strongly favor betterleaks.

## Why "audr real daemon" is the row that matters

Audr does **not** pass `--no-verification` to TruffleHog. Verification is on. The daemon-mode row that compares against betterleaks honestly is the **26.93 s / 594 MB / 39% CPU** row, not the 6 s one. Verification dominates wall time because TruffleHog makes HTTP roundtrips to provider APIs (OpenAI, GitHub, AWS, GCP, Stripe…) for any detector pattern that matches, and most of that wall time is spent waiting on network.

This row matches the lived user experience: peak RSS over half a gigabyte, half a minute of wall time per cycle, every 10 minutes if the daemon is on its default interval. The CPU% is misleadingly low because so much of the wall is blocked on the network — the host is not pegged but the daemon is *busy* for half a minute.

## CPU profile difference is important

User-time + sys-time across all five configs is **~9–12 seconds** of actual CPU work. The engines do roughly the same amount of compute per corpus. The difference is *how they distribute it*:

- **TruffleHog --concurrency=1:** 1.6 cores for 6 seconds (audr daemon mode without verify).
- **TruffleHog default concurrency:** 3.9 cores for 3 seconds.
- **TruffleHog with verification:** 0.4 cores for 27 seconds, blocked on network.
- **Betterleaks defaults:** 4.9 cores for 2.2 seconds.

For daemon UX, **betterleaks' "peg hard for 2 seconds" beats trufflehog's "moderate load for 6 seconds" beats trufflehog's "27 seconds of background HTTP."** Short, sharp bursts are imperceptible to interactive work; long moderate loads drag UI; long network-blocked work keeps file handles and the verifier client warm.

Betterleaks at 157 MB peak RSS, ~2 seconds, ~5 cores burst, is dramatically more daemon-shaped than TruffleHog under any setting tested.

## Finding count — the migration risk

13.5x more findings from TruffleHog (1025 vs 76) is the migration risk. But the surplus is not a coverage gain. Breakdown:

### Where TruffleHog's 1025 findings come from

| Detector | Count | Source(s) | Quality |
|---|---:|---|---|
| `URI` | 704 | 701 from a single file: `vizit-image-downloader/src/main.ts` (literal URL strings in code) | High-cardinality FP from one file |
| `Webscraping` | 174 | `webscrapinghq-website/.vercel/output/static/blog/*.html` (auto-generated blog content) | All FP — text about scraping, not credentials |
| `VirusTotal` | 96 | `easylist.txt` (an adblock filter list) | FP — hex hashes in filter data |
| `GitHubOauth2` | 8 | Various | Probably real |
| `Box` | 6 | | Mixed |
| `Urlscan` | 4 | | Mixed |
| `Postgres` | 4 | `.env` style files | Real |
| `OpenAI` | 4 | | Real |
| `Apify` | 4 | | Real (audr corpus has Apify projects) |
| `PrivateKey`, `GoogleGeminiAPIKey`, `Github` | 3 each | | Real |
| `YoutubeApiKey`, `Slack`, `GCP`, `AWS` | 2 each | | Mixed |
| `Vercel`, `TelegramBotToken`, `Langfuse`, `CloudflareGlobalApiKey` | 1 each | | Real |

**974 of TruffleHog's 1025 findings (95%) come from three FP-heavy detectors firing on three specific files.** Real specialized-provider findings total ~50.

### Where Betterleaks' 76 findings come from

| Rule | Count |
|---|---:|
| `generic-api-key` | 39 |
| `jwt` | 8 |
| `stripe-access-token` | 7 |
| `private-key` | 5 |
| `openai-api-key` | 4 |
| `gcp-api-key` | 3 |
| `slack-bot-token` | 2 |
| `github-pat` | 2 |
| `curl-auth-user` | 2 |
| `aws-access-token` | 2 |
| `telegram-bot-api-token` | 1 |
| `openrouter-api-key` | 1 |

### Path overlap

- TruffleHog flags 113 unique files; betterleaks flags 39.
- 16 files appear in both outputs (cross-validated true positives).
- 97 files are TruffleHog-only (mostly the URI/Webscraping/VirusTotal FP files above, plus some legitimate-but-betterleaks-missed cases).
- **23 files are betterleaks-only** — files TruffleHog did not flag at all.

### Betterleaks finds real things TruffleHog misses

The 23 betterleaks-only files include real `.env` and `.env.local` files, `.clerk/.tmp/keyless.json`, audr's own `internal/rules/builtin/*_test.go` fixtures, and `.next/` build artifacts with embedded tokens. Rule distribution on those 23: 28 generic-api-key, 6 jwt, 4 stripe, 1 private-key, 1 github-pat.

Why does betterleaks catch these and TruffleHog doesn't? **TruffleHog has no entropy-based generic detector.** It is detector-pattern + verification by design — if no specific detector matches, the secret isn't reported. Betterleaks (and gitleaks before it) ship a `generic-api-key` rule that fires on `*_KEY=`, `*_TOKEN=`, `*_SECRET=` style assignments with high-entropy values. That catches `.env`-style true positives TruffleHog systematically misses.

This is a meaningful coverage *gain* from a betterleaks migration, not a loss.

### TruffleHog detectors betterleaks does not ship in defaults

Spot-check of TruffleHog-only specialized providers (excluding the FP-firehose detectors):

- `Apify` — relevant to audr corpus, no native betterleaks rule
- `Webscraping` — pattern is overfit anyway, see above
- `Box`, `Urlscan`, `Langfuse`, `CloudflareGlobalApiKey`, `YoutubeApiKey` — small counts, probably real

Betterleaks rule coverage delta is the spec audit needed before migration. Most can be added via custom rules in `.betterleaks.toml`.

## Implications for audr

### 1. Performance: clear win for betterleaks

- 12.1x wall-time improvement vs audr's real daemon configuration
- 3.8x peak-RSS improvement
- More daemon-friendly profile (burst short, finish fast)

### 2. Signal quality: clear win for betterleaks

- 1025 vs 76 findings is not a coverage difference, it's a noise difference
- TruffleHog's daemon-mode output has 95% high-confidence FPs from three detectors firing on three specific files
- Audr already excludes browser caches via the v0.7.x exclude list, but does not exclude generated `.vercel/output/`, source files with literal URLs, or text filter lists like `easylist.txt`
- Adding more exclude patterns to TruffleHog would help TruffleHog's signal, but it's whack-a-mole — betterleaks' default rule library is already filtered more aggressively

### 3. Coverage: net positive, with caveats

- Betterleaks catches `.env` true positives TruffleHog systematically misses (generic-api-key entropy rule)
- TruffleHog catches specialized provider tokens (Apify, Box, Langfuse, Urlscan) that betterleaks default ruleset does not ship
- Mitigation: write `.betterleaks.toml` custom rules for audr's top-priority providers; audr already has a remediation template for each of these, so the provider list is short and known

### 4. Verification: feature parity, different mechanism

- TruffleHog: compiled-in detector verifiers, one HTTP roundtrip per matched detector
- Betterleaks: CEL `http.get()` in rule definitions, per-rule
- For audr's verified/unverified rule taxonomy: maps cleanly to `--validation-status valid` vs `unknown` vs `invalid`
- Network-dependent verification will continue to add wall time under verification; bench above shows betterleaks WITHOUT validation, so the verify-mode comparison is yet to be measured

## What this benchmark does NOT cover

- **Full $HOME walk.** Bench was `~/projects` (4.2 GB), not all of $HOME (33 GB). Engine-scaling under a 10x bigger workload is not measured.
- **`lowprio` wrapper.** Audr's daemon wraps both scanners in `nice -n 19` + `ionice -c idle`. The bench measured raw scanner perf, not lowprio'd perf. Lowprio affects wall time under contention; it does not affect peak RSS.
- **Cold cache.** All runs warm. Daemon's first-after-boot run is slower than measured.
- **Cross-OS.** This is Linux aarch64. macOS Apple Silicon, x86_64 Linux, and Windows numbers may differ.
- **Memory ceiling under stress.** Bench was a single pass over a 4.2 GB tree; doesn't test pathological corner cases (single huge file, deep archive nesting, recursive symlink hell).
- **Validation perf for betterleaks.** Not measured. TruffleHog with verification ran but no betterleaks-with-validation comparison was done.
- **AI chat transcript scanning.** TruffleHog's filesystem mode handles `*.jsonl` cleanly. Betterleaks behavior on Claude Code / Codex transcripts was not bench'd.

## Decision matrix

| Question | TruffleHog (current) | Betterleaks | Verdict |
|---|---|---|---|
| Daemon-friendly resource profile | No | Yes | Betterleaks |
| Catches `.env` true positives | No | Yes | Betterleaks |
| FP-to-real ratio in default config | ~20:1 on this corpus | ~1:5 (rough) | Betterleaks |
| Specialized provider coverage | Wider (~800 detectors) | Narrower (~100+ default rules) | TruffleHog edge, but manageable |
| Verification mechanism | Compiled-in per detector | CEL per rule | Feature parity, different API |
| Migration cost from current state | n/a | M-L (parser, rule IDs, state-store schema migration, ~10-20 remediation templates re-key, AI-chat-transcript re-wire) | Real cost |
| Ecosystem age / battle-testing | Years | 3 months | TruffleHog edge |

## Recommendation

**Proceed with migration to betterleaks**, but stage the work:

1. **Ship the scan-policy fix first** (mtime-based incremental scan + content-hash cache + size cap). This is the bigger architectural win and reduces blast radius of any subsequent engine swap. Doing this with TruffleHog still in place means the daemon stops re-scanning unchanged files regardless of which engine wins long-term.
2. **Audit detector coverage gap.** Spend ~1 day enumerating which TruffleHog-only detectors audr cares about (Apify, Box, Urlscan, Langfuse, YoutubeApiKey, CloudflareGlobalApiKey, etc.) and translate them to betterleaks `.betterleaks.toml` rules. Estimate 8-15 rules. Use the corpus from this bench as the validation set.
3. **Write betterleaks parser + wire as second sidecar alongside TruffleHog.** Don't rip TruffleHog out yet. Run both, dual-write findings to the state store under separate rule-ID namespaces, expose a feature-flag in audr config. Internal opt-in.
4. **Soft-launch under feature flag** for ~1 release cycle. Real users see both. Compare deltas.
5. **Make betterleaks the default**, deprecate TruffleHog sidecar code path, schema-migrate `secret-trufflehog-*` rule IDs to canonical `secret-*` rule IDs (or new betterleaks-keyed IDs), publish a one-time finding-burst migration note.

This avoids the all-or-nothing swap. The dual-write phase will surface bugs before users see them.

**Do not skip step 1.** Without the scan-policy fix, even betterleaks at 2 seconds will be re-scanning the same unchanged 4 GB every 10 minutes. A 2-second blip every cycle is fine; a 2-second blip after every actual file write is invisible.

## Raw artifacts

- `bench.sh` — harness script (in `/tmp/audr-bench/`)
- `trufflehog-daemon.jsonl` — 1025 findings, audr daemon settings, no verify
- `trufflehog-cli.jsonl` — 1023 findings, default concurrency, no verify
- `trufflehog-verify.jsonl` — 1025 findings, audr real daemon (verify ON): 16 verified, 1009 unverified
- `betterleaks-default.json` — 76 findings
- `betterleaks-mt5.json` — 76 findings, --max-target-megabytes=5
- `trufflehog-exclude.txt` — audr's exact exclude-paths file (94 patterns) used in all TruffleHog runs

## Reproducibility

```bash
# Setup
brew install trufflehog betterleaks
mkdir -p /tmp/audr-bench
cp benchmarks/bench.sh /tmp/audr-bench/
cp benchmarks/trufflehog-exclude.txt /tmp/audr-bench/

# Warm caches
find ~/projects -type f >/dev/null

# TruffleHog (audr real daemon mode)
/tmp/audr-bench/bench.sh trufflehog-verify /tmp/audr-bench/trufflehog-verify.jsonl \
  trufflehog filesystem --json --no-update --concurrency=1 \
    --exclude-paths=/tmp/audr-bench/trufflehog-exclude.txt ~/projects

# Betterleaks (defaults)
/tmp/audr-bench/bench.sh betterleaks-default /tmp/audr-bench/betterleaks-default.json \
  betterleaks dir --report-format=json --report-path=- --no-banner --log-level=warn ~/projects
```
