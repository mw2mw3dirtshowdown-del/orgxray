# OrgXray Case Study — GitHub Secret Discovery at Scale
*Responsible-disclosure pipeline, 2026-11-11*

## Result

A targeted Supabase sweep produced **78 verified LIVE critical credentials**
(service_role JWTs, HTTP 200 confirmed against production REST APIs) from
1,404 candidate files → 373 JWTs → 78 live. A first broad sweep added 5 more.
6 Stripe keys were already dead (401) — GitHub's own scanning covers Stripe,
not Supabase. All outcomes logged to `verification-outcomes.jsonl`;
79 disclosure drafts generated (redacted, human-review only, never auto-sent).

## Method

- GitHub code-search API: 13 provider-prefix queries + 300 contextual queries +
  6 targeted Supabase queries (1,404 files) → 373 JWTs
- Triage: 184 unique non-fixture candidates → 145 extractions → 72 after
  token-efficiency filtering; Supabase sweep: JWT decode + role=service_role
  filter → 373 → 78 verified live
- Verification: read-only HTTP probes only (Supabase `/rest/v1/`, Stripe `/v1/account`)
- Every outcome persisted to `verification-outcomes.jsonl`; drafts never auto-sent

## Engineering notes (what makes this non-trivial)

- BPE token-efficiency filter ("Rare Not Random") calibrated on own corpus:
  4,952 findings → 13.6% affected at threshold 2.5; threshold curve measured
  at 2.0/2.2/2.5/2.8 instead of a magic number
- Structural word/compound detection (Norwegian-aware): compounds demoted to
  `low` not dropped — `fjellby`-style passwords survive as weak-but-real
- Passphrase tiling via bounded DP (≤128-char runs) — 3.2KB PEM blocks scan
  in ~1.5ms
- Build provenance: host-computed git SHA + dirty flag injected into container
  via env; guard-shim refuses stale bind-mounts
- Precision honesty: 37-unit verification pass → 1 LIVE / 5 DEAD / 8
  unverifiable / 23 fixture; the bottleneck identified as generic-rule
  false positives (env-var names, checksums, UN/LOCODE), not threshold tuning

## Why Supabase specifically

GitHub's native secret scanning covers Stripe/AWS/GitHub tokens aggressively —
all 6 `sk_live_` keys found were already dead (401). Supabase `service_role`
JWTs and `sb_secret_` keys are **not covered** by push protection and leak at
scale from student/hobby `.env` commits.

## Artifacts

- `verification-outcomes.jsonl` — machine-readable LIVE/DEAD/unverifiable log
- `reports/disclosures-*/` — disclosure drafts (redacted, human-review only)
- Scanner: single-file Python CLI, containerized `--network none` sandbox,
  incremental scans keyed to repo HEAD
