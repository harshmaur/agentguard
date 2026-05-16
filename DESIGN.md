# DESIGN.md — audr design system

Single source of truth for audr's three rendering surfaces. When the surfaces
drift visually, this doc is the arbiter. When the doc and a surface disagree,
fix the doc OR fix the surface — don't let both stay wrong.

## Surfaces

| Surface | Lives in | Role | Audience |
|---|---|---|---|
| audr-web (marketing) | `audr-web/` (separate repo, Astro) | Landing page, docs, product narrative | Visitors deciding whether to install |
| Dashboard | `internal/server/dashboard/` | Live operational view of the daemon | Running users, day-to-day |
| HTML report | `internal/output/report.html.tmpl` | Frozen evidence snapshot from one-shot `audr scan` | CISO / auditor reading offline |

The marketing site sells the product. The dashboard is the product. The
report is the artifact the product produces.

### What's shared across surfaces

- Severity vocabulary and order: **Critical → High → Medium → Low**
- Kind taxonomy on findings: **package / secret / agent-rule / other**
- The mental model: severity is the primary axis, kind is row-level metadata
- Information architecture: severity-sectioned finding lists in both
  dashboard and report
- The "verdict / metric strip / findings" reading order
- Brand mark: `A U D R` letterspaced, monospace, no graphic logo

### What is intentionally NOT shared

- **Palette ambition.** Dashboard uses vivid operational reds
  (`#e63a30`); report uses editorial earth-tones (`#6F0A12` oxblood). The
  dashboard demands at-a-glance reading at a screen you're glancing at;
  the report demands long-form readability for someone sitting with it.
- **Typography.** Dashboard declares IBM Plex; report ships embedded
  Geist + Instrument Serif. See the typography section for why this
  isn't unified yet and how to think about that drift.
- **Motion.** Dashboard has pulse-dots, fade transitions, strikethrough
  animations. Report has no motion — it's a static artifact.
- **Interactivity.** Dashboard is live (SSE, expand-to-detail, filter
  chips that re-filter, animations). Report has filter chips that work
  via inline JS but is otherwise static.

## Typography

### Current state

| Surface | Mono | Sans | Display |
|---|---|---|---|
| Dashboard | `"IBM Plex Mono"` declared, system fallback live | `"IBM Plex Sans"` declared, system fallback live | (none) |
| HTML report | `"Geist Mono"` embedded woff2 | `"Geist"` embedded woff2 (variable 400-600) | `"Instrument Serif"` embedded woff2 |
| audr-web | IBM Plex Mono + IBM Plex Sans | — | — |

**The dashboard does not currently embed its declared fonts.** The CSS
declares Plex but doesn't include `@font-face` rules pointing at
woff2 files. Modern dev machines tend to have neither installed, so
the visible fonts are system fallbacks (`ui-monospace`, `system-ui`).

This is intentional for v1 but worth tracking: matching audr-web's
exact rendering on the dashboard requires shipping Plex woff2 files
through `//go:embed`, the same way the report ships Geist + Instrument
Serif. Estimated cost: ~85 KB after base64 inflate, similar to the
report's font block.

### Type roles

| Role | Where it appears | Voice |
|---|---|---|
| Display | Report verdict lead, section anchors | Slow, editorial, "this is what we found" |
| Body | Finding descriptions, prose | Readable at 14-15px over multiple paragraphs |
| Mono | Code blocks, severity labels, paths, metric numbers, eyebrows | Terminal-adjacent — "this is real, not editorial" |

Display type only appears in the report. The dashboard is all mono +
sans because operational tools shouldn't editorialize.

## Color tokens

### Dashboard palette (dark-only, operational)

```
--bg          #0e0e0c   page background
--surface     #1a1a17   raised surfaces (expanded finding rows)
--surface-2   #232320   inset surfaces (code blocks, evidence)
--text        #f5f5f0   primary text
--text-muted  #9c9c95   secondary text, meta
--border      #2a2a25   hairlines

--critical    #e63a30   severity, vivid
--high        #d9711f
--medium      #c49b2c
--low         #4a7bb7   intentionally blue, not green — Low is not "safe"
--ok          #4fa86e   resolved / clean states only
```

### HTML report palette (light + dark, editorial)

The report has an intentionally softer palette. Severity colors are
muted oxblood / burnt amber / mustard / slate, not vivid signal colors.
Reading the report should feel like reading a memo, not staring at a
dashboard. See `internal/output/report.html.tmpl` lines 41-99 for the
full token block (separate `:root` for light and dark via
`prefers-color-scheme`).

### Why not unify

The earlier design spec (May 13) called for unifying all three surfaces
on dashboard tokens. We deliberately did NOT do this — the report's
editorial palette is too valuable to lose to operational consistency.
The structural unification (severity sections, kind badges) gets you
90% of the perceived consistency benefit; matching exact hex codes
gets you 10% at the cost of erasing the report's voice.

## Severity language

Spelled-out names everywhere, never SEV-N or P0/P1/P2/P3. The four
levels:

| Token | Surface label | Means |
|---|---|---|
| `critical` | CRITICAL | Active exploitation path. Fix before next session. |
| `high` | HIGH | Realistic exploitation path under common conditions. |
| `medium` | MEDIUM | Risky configuration. Will become a real problem under specific conditions. |
| `low` | LOW | Hardening recommendation. No live attack path observed. |

Rules:

- Severity is **conveyed by color AND by the all-caps label**. Never by
  color alone (WCAG 2.1 AA + screen reader baseline).
- CRITICAL + HIGH are always expanded by default in the dashboard.
  MEDIUM + LOW are collapsed to a count.
- "Resolved today" or "clean" do not flood the UI with green. The
  product's job is to report risk, not to celebrate the absence of
  risk. See the "Voice" section.

## Kind taxonomy

A finding's kind is a row-level signal, not a section divider. The
four kinds:

| Kind | Source | Locator shape |
|---|---|---|
| `package` | OSV-Scanner via depscan | `{ecosystem, name, version, manifest_path}` |
| `secret` | Betterleaks | `{path, line}` plus the redacted match |
| `agent-rule` | audr's own rules under `internal/rules/builtin/` | `{path, line}` (file kind) |
| `os-package` | OSV-Scanner via ospkg | `{manager, name, version}` |

Dashboard and report both render kind as a small uppercase badge next
to the severity pill on each finding. The filter chips at the top of
each surface can hide-by-kind without re-grouping the document — kind
is metadata, not structure.

### Why kind is row-level, not a section

Earlier versions of the report had three top-level sections (Package
Vulnerabilities / Secrets / Other). We restructured because that
shape forces a reader who wants "the worst stuff" to walk three
sections in parallel. With severity-grouped sections + kind badges, a
reader's first scan is "Critical → fix today" regardless of kind, and
filtering by kind is one click when needed.

## Component vocabulary

These names are durable and should be reused everywhere. When
introducing a new component, check whether it slots into one of these
patterns before naming it something new.

| Component | Role | Lives on |
|---|---|---|
| **Eyebrow** | Top strip with brand mark + version + classification | Dashboard, report |
| **Verdict** | One-sentence lead + supporting clause + severity bar | Report only (operational UI doesn't need a "lead") |
| **Metric strip** | 4 numbers in a row: Open total, Critical count, High count, Resolved today (dashboard) or Crit/High/Med/Low + Chains (report) | Dashboard, report |
| **Filter chips** | Toggle pills for kind × severity | Dashboard, report |
| **Severity section** | Header + collapsed/expanded list of findings of one severity | Dashboard, report |
| **Finding row** | Compact summary + expand-to-detail | Dashboard, report |
| **Kind badge** | Per-finding uppercase tag: PACKAGE / SECRET / AGENT-RULE / OTHER | Dashboard, report |
| **Severity pill** | Per-finding uppercase tag: CRITICAL / HIGH / MEDIUM / LOW | Dashboard, report |
| **Banner stack** | Persistent strip below top bar, one row per condition | Dashboard only |
| **Scan-progress strip** | Per-category state (RUNNING / OK / ERROR / OFF) while scanning | Dashboard only |
| **Browse-by-file** | Secondary view re-grouping findings by path | Report only |
| **Attack chain** | Editorial narrative across multiple findings with attacker outcome callout | Report only |

### Banner kinds (dashboard)

| Kind | Tone | Triggers |
|---|---|---|
| `info` | Calm, blue tint | Update available; remote-FS roots intentionally skipped |
| `warn` | Amber tint (default) | Scanner unavailable; inotify limit demoting watches |
| `error` | Red tint | Scanner errored on last cycle |

Every banner carries: a short tag (5-15 chars uppercase), the
human-readable text, optionally an inline `<code>` fix command, and
optionally a link. A dismiss button hides the banner for the
remainder of the session; it returns on next daemon restart if the
condition persists.

## Information architecture

Reading order (3-second-scan goal):

1. **Daemon state pulse-dot** (top bar): am I being watched?
2. **Metric strip** (4 numbers): am I OK? what's worst? what's new?
3. **Severity-sectioned findings list**: what do I do next?

Findings are grouped by **severity, not by category**. Category
appears as a row-level kind badge. Within a severity bucket, findings
sort by first-seen DESC.

In the report, that primary view is followed by an editorial layer
(verdict + attack chains, both at the top because they answer "should
I be worried in general?") and a secondary view (Browse by file) at
the bottom for "I want to see what's wrong with file X".

## Motion

| Affordance | Surface | Behavior |
|---|---|---|
| Pulse-dot | Dashboard top bar | 2s ease-in-out; freezes on SLOW, hides on PAUSE/OFFLINE |
| Spinner | Dashboard scan-progress | 0.9s linear rotate, only when scan is active |
| Resolved-finding | Dashboard | strikethrough + fade-out (700ms) → collapse (500ms) → DOM remove (5s after trigger) |
| Banner dismiss | Dashboard | instant, no animation |
| Copy AI prompt | Dashboard | text swap + 200ms outline pulse, then revert after 2s |

**`prefers-reduced-motion: reduce`** disables every animation above.
Pulse-dot falls back to static, spinner falls back to a static
ring, resolved-finding skips the transitions and removes the row
immediately.

The report has zero motion. It's a static artifact.

## Accessibility baseline

WCAG 2.1 AA. Specifics:

- **Contrast.** Dashboard body text `#f5f5f0` on `#0e0e0c` is ~15:1.
  Severity colors against the dark background verified at 3:1+
  (chrome contrast). The dashboard's `--low: #4a7bb7` was chosen for
  its 3:1 ratio against `#0e0e0c` specifically.
- **Severity NOT conveyed by color alone.** Every finding row carries
  the all-caps severity label as text, not just a colored bar.
- **ARIA landmarks.** `<header role="banner">`, `<main>` for the
  findings list, footer at the bottom. SSE event handlers update
  `aria-live="polite"` regions so screen readers announce new findings.
- **Reduced motion.** Honored via `@media (prefers-reduced-motion: reduce)`.
- **Keyboard nav** (deferred to v1.x — Tab/Enter currently work via
  default browser handling; J/K row nav and C-to-copy not yet wired).

The HTML report inherits the same baseline because it's a single
static page — screen readers can navigate it via heading structure.

## Voice

The product reports risk. It does not celebrate the absence of risk.

**Yes:**
- "No findings on this scan."
- "0 open findings · last scan 2 min ago"
- "Clean. No developer-machine security findings."

**No:**
- "All clear!"
- "🎉 You're safe."
- "Everything is awesome."
- Green floods on the clean state. The cleanest state is calm, not
  rewarding.

The same posture goes for resolution. A finding gets a strikethrough
and a fade, then disappears. The metric strip's "Resolved today"
ticks up with a brief flash. No confetti, no toast, no "Nice work!"

## Surface drift — current known gaps

These are NOT bugs. They're documented divergences:

1. **Dashboard fonts** declare IBM Plex but don't embed it — falls
   back to system mono/sans. Phase 5b ships embeds when font work
   becomes a priority.
2. **Light-mode report vs dark-only dashboard.** Intentional. Report
   needs to print on paper for CISOs. Dashboard never prints.
3. **Severity palette divergence** between dashboard (vivid) and
   report (muted earth-tones). Intentional.
4. **No keyboard nav on dashboard** beyond default browser Tab/Enter
   focus traversal. v1.x.
5. **OS notifications** spec'd but not built. v1.x. When built,
   notification body copy follows the same voice rules (no
   celebration; CRITICAL only).

## How to evolve

When changing visual behavior:

1. Read this doc first. If the change conflicts with a documented
   rule, the rule wins unless you're explicitly here to change it.
2. If you're changing both the dashboard AND the report, change
   them in the same PR. Diverging the two by accident is the
   primary failure mode.
3. If you're adding a new component, name it from the vocabulary
   above when possible. If you genuinely need a new name, add it to
   the Component vocabulary table in the same PR.
4. Update `docs/sample-report.html` when the report template
   changes (CI gate enforces this).
5. Run `go test -race -count=1 ./...` — the output package tests
   include a `TestHTML_GroupsFindingsBySeverity` that anchors the
   severity-grouping structure.

This doc is short on purpose. If you find yourself wanting to add
more, ask first whether the addition belongs in code comments,
component-level READMEs, or here.
