# OrgXray

Local-first reconnaissance and Git-history secret scanner for **authorized
responsible disclosure**. Single-file Python CLI + containerized sandbox +
GitHub code-search sweeps.

**Verified result (2026-11-11):** an authorized disclosure pipeline that
finds credential exposures in public code, verifies each one read-only,
and produces redacted disclosure drafts — never auto-sent. See
`CASE-STUDY.md` for the full pipeline and honest numbers.

## What it does

- `orgxray scan|history|members|quick|deep` — clone org repos, run
  gitleaks + internal regex engines over full Git history, incremental
  scans keyed to repo HEAD
- `orgxray triage|shortlist|disclose|report` — finding quality tiers,
  evidence-backed shortlist, disclosure drafts (never auto-sent)
- `orgxray watch` — re-scan on schedule
- `gh-sweep.py` — GitHub code-search across provider prefixes and
  contextual queries, feeding the same verification pipeline

## Detection philosophy (the non-obvious parts)

- **BPE token-efficiency** ("Rare Not Random", cl100k_base): secrets are
  *rare* text, not just high entropy. Threshold curve measured on own
  corpus — 2.0/2.2/2.5/2.8 → 693/487/439/384 filtered of 4,718
  candidates. ~13.6% of generic candidates affected at 2.5.
- **Norwegian-aware word layers**: cl100k_base is English-tuned; a
  Norwegian frequency list (CC BY-SA 4.0, hermitdave/FrequencyWords)
  plus 10k-morpheme compound tiling keeps `fjellby`-style passwords
  alive — compounds and passphrases demote to `low`, never dropped.
  Prose (`_wordlike` ≥60% dictionary coverage) is the only discard.
- **Bounded DP** for word splitting (≤45/≤128-char runs): 3.2KB PEM
  block ≈1.6 ms/call — no quadratic blowup.
- **Structural, not prefix lists**: `_wordlike` requires dominant
  dictionary coverage of the whole value, so foreign provider formats
  containing `secret_`/`token_` survive automatically.
- **Prefilter** on author + commit-subject before regex; path filters
  (`node_modules`, fixtures) — støy koster aldri regex-tid.
- **Components**: `*.p8` private keys require a matching `apple-key-id`
  (filename or nearby `key_id`) — missing → quality `low`, never silent.

## Supply-chain integrity

- `Dockerfile` installs a **guard-shim**, not a copied binary: the image
  refuses to run without a read-only bind-mount of live code — a stale
  COPY would produce normal-looking findings from an outdated detector.
- **Build stamp** `[orgxray] build <sha256@date+commit+dirty>` printed
  at scan start and logged per-run; host computes it (container can't
  see git metadata) and injects via `ORGXRAY_BUILD_STAMP`.

## Verification discipline

Every finding is classified verified / dead / unverifiable / fixture —
never inferred. Verification is **read-only only** (HTTP GET probes,
`openssl` cert checks). Secrets are redacted in all reports; raw
findings and cloned repos never leave the local data dir.

Honest precision note: the bottleneck is generic-rule false positives
(env-var names, checksums, UN/LOCODE), not threshold tuning — measured
0/40 plausibly-real in a manual 20+20 sample across the TE boundary.

## Layout

```
orgxray            single-file CLI (the scanner)
orgxray-sandbox    Docker wrapper (network-none sandbox)
gh-sweep.py        GitHub code-search sweep
test_orgxray.py    regression tests
Dockerfile         sandbox image (guard-shim, tiktoken baked in)
AGENTS.md          internal engineering notes (detection internals)
CASE-STUDY.md      verified results + methodology
```

## Quick start

```bash
pip install tiktoken gitleaks   # or use the container
./orgxray quick <repo-path>     # local scan
./orgxray-sandbox scan <org>    # sandboxed org scan
python3 gh-sweep.py             # GitHub-wide prefix sweep
```

## License

Code: MIT. Bundled word/morpheme lists derive from
`hermitdave/FrequencyWords` — content **CC BY-SA 4.0** (ShareAlike
applies to derived lists distributed with the tool; see AGENTS.md).
