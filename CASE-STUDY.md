# OrgXray Case Study — GitHub Secret Discovery at Scale
*Responsible-disclosure pipeline, 2026-11-11*

## Result

An authorized secret-discovery pipeline produced **verified credential-exposure
findings** across public code repositories. Every candidate was checked
read-only before classification; outcomes are logged to
`verification-outcomes.jsonl` and disclosure drafts are generated redacted,
human-review only, never auto-sent.

## Method

- GitHub code-search API: provider-prefix + contextual queries → candidate files
- Triage: non-fixture candidates → extractions → token-efficiency filtering →
  provider-format decode → read-only verification
- Verification: read-only HTTP probes only — no writes, ever
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
- Precision honesty: a 37-unit verification pass showed the bottleneck is
  generic-rule false positives (env-var names, checksums, UN/LOCODE),
  not threshold tuning

## Artifacts

- `verification-outcomes.jsonl` — machine-readable outcome log
- `reports/disclosures-*/` — disclosure drafts (redacted, human-review only)
- Scanner: single-file Python CLI, containerized `--network none` sandbox,
  incremental scans keyed to repo HEAD
