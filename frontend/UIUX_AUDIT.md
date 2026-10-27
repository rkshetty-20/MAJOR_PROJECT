# FraudGuard — UI/UX Audit Matrix (Phase 1)

Scope: application-wide audit of the React + Vite + TypeScript + Tailwind SOC frontend, performed by static inspection of the actual source in `frontend/src/`. This is the pre-implementation audit required before the redesign. Visual "before/after" screenshots are intentionally out of scope for this pass (see Delivery note).

Method: for each module the audit records current layout, main usability problems, redundant elements, missing states, accessibility issues, components worth reusing, proposed changes, and the risk to existing functionality. It also records the cross-cutting findings, the pre-existing runtime errors (kept separate from design work per the spec's critical rule), the duplication inventory, and which findings the Foundation milestone (Phases 1-3) already addresses versus those deferred to page-level milestones.

Legend for proposed-change status:
- ADDRESSED (M1): handled by the foundation milestone now.
- LATER (P#): deferred to the corresponding page/phase milestone (Phases 4-16).

## Design-system baseline observed before this work

- No centralized design tokens existed: `tailwind.config.js` had an empty `theme.extend`, and `src/index.css` was ~15 lines. Colors (`slate-950`, `slate-900`, `indigo-400/500/600`, `emerald-400`, `rose-500`, `amber-500`, raw `#030712`/`#0f172a`) were hardcoded and repeated across every component.
- Navigation is state-based (`PageId` in `App.tsx`), not route-based. This is preserved.
- A partial primitive set already existed in `src/components/ids/primitives.tsx` (Card, Tooltip, Skeleton/SkeletonPanel, Severity/Verdict badges, ThreatGauge, MeterBar) but only served the IDS module.
- Loading/empty/error handling was inconsistent: some panels had explicit N/A states (e.g. `SecurityOverview` metrics), others had only a spinner or a bare error banner.

---

## Module audit matrix

### 1. Dashboard (`DashboardPage.tsx`, `SecurityOverview.tsx`, `DetectionRiskOverview.tsx`, `AttackCoverage.tsx`)
- Current layout: full-width column — a 7-metric overview strip, a two-track (intrusion/phishing) coverage grid with fixed `h-64` panels, then a detection/risk overview. No page-level title.
- Main usability problems: no consistent page header/breadcrumb; metric strip is a dense 7-column grid that can feel cramped at mid widths; section headers use ad-hoc colored uppercase text (`text-emerald-500`, `text-amber-500`) rather than a shared component.
- Redundant elements: two similar "coverage" panels differ only by a hardcoded accent color; metric tiles are bespoke markup repeated 7x.
- Missing states: coverage panels assume data exists; no explicit empty/unavailable treatment at the panel level (metric tiles already do N/A well).
- Accessibility issues: section `<h2>` hierarchy is fine; metric tiles rely on color for tone; refresh control is a bespoke button without a consistent focus ring.
- Reusable components: the N/A metric tile pattern in `SecurityOverview` is exactly what `MetricCard` generalizes.
- Proposed changes: adopt `PageHeader` + `MetricCard` + `StatusBadge`; replace bespoke refresh button with `Button`; make coverage heights responsive. LATER (P4).
- Functional-preservation risk: LOW — presentation only; must keep the real `/api/overview`, `/api/risk`, `/api/detections` values and N/A semantics (never fabricate a metric).

### 2. Intrusion Detection (`IntrusionDetectionPage.tsx` -> `components/ids/*`)
- Current layout: thin wrapper delegating to `IntrusionDetectionWorkspace` (payload form, results, history, rules, threat intel, packet views).
- Main usability problems: the module is self-contained and visually diverges from the rest of the app (own primitives, own card styling).
- Redundant elements: IDS `Card`/`Tooltip`/`Skeleton` duplicated the shared look; now consolidated.
- Missing states: workspace handles most states; no page-level header describing what submitting a payload does.
- Accessibility issues: icon-only affordances in some panels; no page title for screen readers.
- Reusable components: `ids/primitives` (ThreatGauge/MeterBar stay; Card/Tooltip/Skeleton now re-export from `ui`). ADDRESSED (M1) for the primitives consolidation; the page redesign (title + explainer) is LATER (P5).
- Functional-preservation risk: MEDIUM — must not change detection behavior or result shapes; IDS panels depend on exact Card/Tooltip props (preserved via re-export).

### 3. Phishing Detection (`PhishingDetectionPage.tsx`)
- Current layout: URL form + result card; heuristic vs reputation surfaced in the result.
- Main usability problems: inline validation is minimal (empty guard only); the "heuristic does not fetch the URL" explanation and reputation-unavailable vs clean distinction should be more prominent.
- Redundant elements: custom button/markup repeated instead of `Button`/`Badge`.
- Missing states: "reputation unavailable" and "analysis failed" are handled but styled ad hoc; no page header.
- Accessibility issues: form label association and error announcement should be verified; heuristic score must not be phrased as a calibrated probability.
- Reusable components: `Button`, `StatusBadge`, `ErrorState`, `MetricCard`.
- Proposed changes: adopt shared kit; strengthen validation + explanatory copy; LATER (P6).
- Functional-preservation risk: LOW — do not change the `/api/detect/phishing` contract or heuristic semantics.

### 4. Attack Simulation (`AttackSimulationPage.tsx`, `AttackSimulation.tsx`, `SyntheticDataGenerator.tsx`)
- Current layout: simulator + raw dataset generator sections with copy/export/replay actions.
- Main usability problems: several large cards placed adjacently without a clear sectioned progression (select -> configure -> run -> dataset -> replay -> evaluation); `dsMessage` success/error is ad hoc.
- Redundant elements: repeated local button class strings (`btnPrimary`/`btnSecondary` style patterns) instead of a shared `Button`.
- Missing states: success banner timing vs backend confirmation must be verified; no unified loading/empty states.
- Accessibility issues: segmented controls/selects need labels; duplicate-submit prevention relies on local flags.
- Reusable components: `Button`, `SectionHeader`, `ConfirmationDialog` (for irreversible actions), `Toast`.
- Proposed changes: section the page into the documented progression; LATER (P7).
- Functional-preservation risk: MEDIUM — simulation/dataset/replay flows and `EvaluationRun` persistence must remain unchanged.

### 5. Scenario Studio (`ScenarioStudioPage.tsx`, `ScenarioLifecycleExplorer.tsx`)
- Current layout: NL request -> propose -> validate -> compile -> replay -> lifecycle; local `btnBase/btnPrimary/btnSecondary` class constants.
- Main usability problems: bespoke button constants; proposal must not appear "executed" before validation/compile success (already partially enforced by the workflow labels).
- Redundant elements: `btnBase` etc. re-implement `Button`.
- Missing states: LLM provider-unavailable path must keep deterministic simulation reachable and show a useful error.
- Accessibility issues: multi-step controls need clear labels and status announcements.
- Reusable components: replace local button constants with `Button`; use `StatusBadge` for validation state. LATER (P7).
- Functional-preservation risk: MEDIUM — do not change the validate/compile gating or provenance.

### 6. Visualization & Investigation (`VisualizationInvestigationPage.tsx`, `visualization/*`)
- Current layout: discovery dashboard when no context; multi-pane investigation (timeline, evidence inspector, relationship graph, anatomy) when selected.
- Main usability problems: very large components (`AttackAnatomy.tsx` ~916 lines, page ~673 lines); desktop/mobile column balance and evidence density need tuning; empty/space usage can feel like a large container.
- Redundant elements: multiple bespoke panels/cards that map to `Card`/`SectionHeader`/`MetricCard`.
- Missing states: "missing evidence" is shown in places; should be consistent across all panes.
- Accessibility issues: relationship graph and charts need non-color cues and keyboard reachability.
- Reusable components: adopt `Card`/`MetricCard`/`EmptyState`/`Mono` for IDs. LATER (P8).
- Functional-preservation risk: MEDIUM — must keep real timestamps/records and not invent stages/relationships. `AttackAnatomy` fetches `/api/ml/status` as data (kept).

### 7. Adaptive Learning (`AdaptiveLearningMetrics.tsx`, `LLMLearningAnalyst.tsx`)
- Current layout: tabbed panel (status / history / lifecycle / analyst) inside a fixed `h-[600px]` container.
- Main usability problems: fixed height is brittle; model-overview dataset-registry and candidate-comparison requirements (Phase 9.1/9.2/9.5) are only partially present; "Engine Unavailable" is a full-panel block rather than an inline degraded state.
- Redundant elements: repeated slate card styling and a bespoke retry button; a second fixed-height wrapper in `App.tsx`.
- Missing states: untrained vs unavailable ML distinction; candidate activation must never look active just because training completed.
- Accessibility issues: tab affordances should expose `aria-selected`/roles; color-only status dots.
- Reusable components: `Card`, `StatusBadge`, `ErrorState`, `Button`, `MetricCard`, `Mono`; use the shared `useSystemHealth` ML signal for the degraded banner. LATER (P9).
- Functional-preservation risk: HIGH — training/accept/rollback and analyst safeguards must not change; `AdaptiveLearningMetrics.test.tsx` asserts the current `/api/ml/status` failure path, so the fetch behavior is intentionally preserved.

### 8. Security Copilot (`SecurityAssistant.tsx`)
- Current layout: chat pane with context indicator and streaming responses (`streamChat`).
- Main usability problems: message alignment/readability of long answers, suggested-prompt relevance to the selected investigation, copy-response; oversized bubbles/empty space per Phase 10.
- Redundant elements: bespoke controls vs `Button`.
- Missing states: provider failure must show a useful error and preserve the rest of the app (currently "Failed to fetch" — see errors section).
- Accessibility issues: live-region announcements for streamed text; distinguish user vs assistant messages semantically.
- Reusable components: `Button`, `ErrorState`, `Toast`. LATER (P10).
- Functional-preservation risk: MEDIUM — keep SSE parsing and context construction (covered by `api.test.ts`).

### 9. Event Logs (`RecentEventsTable.tsx`, `SecurityEventModal.tsx`)
- Current layout: filter toolbar (search + risk filter) over a dense table with row selection.
- Main usability problems: no time/category/source filters beyond risk + text; no pagination/sorting visible at entry; desktop density vs responsive layout.
- Redundant elements: bespoke search input and refresh button.
- Missing states: empty vs error vs loading handled locally; raw vs normalized payload view needs clearer separation in the modal.
- Accessibility issues: table headers/scope, row-selection keyboard support; untrusted values must render safely.
- Reusable components: `Card`, filter toolbar, `Mono` for IDs/hashes. LATER (P11).
- Functional-preservation risk: LOW — read-only view of persisted events; must not expose secrets.

### 10. Settings (`SettingsPage.tsx`)
- Current layout: "Configuration & Health" page with a local `Section` card and a grid of health/config/preferences sections.
- Main usability problems:
  - Non-functional controls: a "Light Mode" theme option and a "Default Landing Page" select that do not actually change the app (`App.tsx` always starts at `dashboard`; `savePreferences` only writes `localStorage` and fires `window.alert`). This violates Phase 12 ("Do not create fake configuration controls that have no backend implementation"; "avoid presenting inert buttons as functional settings").
  - Feedback uses `window.alert` instead of the shared notification system.
- Redundant elements: local `Section` duplicates `Card`; hardcoded health pill styling duplicates `StatusBadge`.
- Missing states: config load error is handled (retry) — good; but "LLM provider status" section referenced by Phase 12 is not present.
- Accessibility issues: `window.alert` is not a designed dialog; selects are labeled (good); color-only status pills.
- Reusable components: `Card`, `StatusBadge`, `Button`, `ConfirmationDialog`/`Toast` for save feedback. LATER (P12).
- Functional-preservation risk: LOW — display of real `/api/system/config`; removing/relabelling fake controls must not break the real preferences that do work.

### 11. Backend Status & global notifications (`App.tsx`, `Sidebar.tsx`)
- Current layout: sidebar footer showed a single backend dot + latency + API URL + "Simulation Mode".
- Main usability problems: connectivity was inferred only from `/health`, not distinguishing per-service health (ML, integrity) — the exact gap Phase 3.3 calls out.
- Redundant elements: `App.tsx` owned ad-hoc connection state that duplicated what a shared provider should own.
- Missing states: no degraded state distinct from connected/disconnected; no per-service indicator.
- Accessibility issues: status text was present but dots were color-only; nav lacked `aria-current`.
- Reusable components: shared `useSystemHealth` provider + `StatusBadge`/`Mono`. ADDRESSED (M1).
- Functional-preservation risk: LOW — additive; keeps `/health` semantics and adds `/api/system/config` service signals.

---

## Cross-cutting findings

- Tokens: color/radius/shadow/typography were scattered everywhere. ADDRESSED (M1) by `tailwind.config.js` semantic tokens + `:root` CSS variables in `index.css`. Page-level migration to those tokens is LATER (per page).
- Shared components: `Button`, `Card`/`SectionHeader`, `PageHeader`, `MetricCard`, `StatusBadge`/`RiskIndicator`, `EmptyState`/`ErrorState`/`Skeleton`, `Tooltip`, `ConfirmationDialog`, `Toast`/`useToast`, `Mono` now exist under `src/components/ui/`. ADDRESSED (M1); pages adopt them in their milestones.
- Accessibility baseline: global `:focus-visible` outline and `prefers-reduced-motion` added; sidebar `aria-current`, labeled nav groups, labeled mobile menu button. ADDRESSED (M1). Deeper per-workflow a11y (dialogs, live regions, keyboard tables) LATER (P16).
- Forms/feedback: consistent `Button` loading/disabled + `Toast` + `ConfirmationDialog` provided; rollout across forms LATER (P13).
- Test baseline: frontend suite was present but unwired (no `test` script, no vitest config) so it never ran. ADDRESSED (M1): vitest wired (jsdom + setup), baseline established — 10 files / 43 tests green.

## Pre-existing runtime errors (reported separately, not silently fixed)

Per the spec's critical rule, these are functional findings distinct from the redesign. Root cause is backend/service availability; the UI must show honest degraded states. Backend fixes are out of scope for the UI foundation milestone.

- `Engine Unavailable — Failed to get ML status`: `AdaptiveLearningMetrics.tsx` fetches `/api/ml/status` (`:59`) and renders a full-panel "Engine Unavailable" on failure (`:112`); `visualization/AttackAnatomy.tsx` also fetches `/api/ml/status` (`:178`) to embed ML data. Disposition: keep fetch behavior (guarded by `AdaptiveLearningMetrics.test.tsx`); a later milestone converts the full-panel block into an inline degraded state that distinguishes "no model trained" from "ML service unavailable" (Phase 14 untrained-vs-unavailable).
- `Failed to complete simulation run`: surfaces from the simulation flow (`AttackSimulationPage.tsx` / simulator API). Disposition: keep; the page milestone must show an actionable error + retry that does not issue duplicate simulations (Phase 14).
- `Security Copilot — Failed to fetch`: from `SecurityAssistant.tsx` chat/stream. Disposition: keep; the Copilot milestone must show a useful provider error and preserve the rest of the app (Phase 10).

No error was hidden, and no mock data was substituted. The foundation milestone's service-aware status makes ML/integrity/degraded state visible at the shell without claiming all modules are healthy just because `/health` responds.

## Duplication inventory (fix before adding new)

- IDS `Card`/`Tooltip`/`Skeleton`/`SkeletonPanel` duplicated generic patterns. RESOLVED (M1): moved to `ui/`, `ids/primitives.tsx` re-exports them so its 8 import sites are untouched; IDS-only typed pieces (severity/verdict styling, ThreatGauge, MeterBar) remain.
- `ScenarioStudioPage` `btnBase`/`btnPrimary`/`btnSecondary` and `SettingsPage` `Section` re-implement `Button`/`Card`. LATER: replace at each page milestone.
- Repeated hardcoded health pills and refresh buttons across pages. LATER: replace with `StatusBadge`/`Button`.

## What the Foundation milestone (Phases 1-3) changes vs what stays

- Changed now: `tailwind.config.js` (tokens), `src/index.css` (variables + focus + reduced motion + scrollbar), new `src/components/ui/*` kit, `src/components/ids/primitives.tsx` (re-export), new `src/hooks/useSystemHealth.tsx`, `src/components/Sidebar.tsx` (tokens + a11y + service indicators), `src/App.tsx` (health provider + service indicators + stray-comment fix + mobile a11y), `vite.config.ts`/`package.json` (vitest wiring), new tests (`ui/__tests__/ui.test.tsx`, `components/__tests__/Sidebar.test.tsx`).
- Intentionally not changed: detection/simulation/phishing/learning business logic, thresholds, evidence integrity, `PageId` routing semantics, and the `/api/ml/status` data fetches in the pages. No new runtime dependencies.
- Deliberate deviation: `AdaptiveLearningMetrics`/`AttackAnatomy` were not migrated to the shared health hook. They consume the full `MLStatus` payload (not a health boolean) and run on different pages, so no duplicate polling exists; migrating them would break their data rendering and `AdaptiveLearningMetrics.test.tsx`. The shell instead sources service health from `/api/system/config`, satisfying Phase 17 (no duplicate polling) and Phase 3.3 (service vs connectivity) without regressions.

Delivery note: before/after screenshots (Phase 20 item 2) were explicitly de-scoped for this pass; verification is via the test/build/dev-smoke outputs and this written matrix.
