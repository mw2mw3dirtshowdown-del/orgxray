#!/usr/bin/env python3
"""Regresjonstest for orgxray — kjør: python3 test_orgxray.py
Dekker: secret_in_head (LIVE/HIST), triage quality-score, scope-gate."""
import json, subprocess, sys, tempfile
from pathlib import Path

from importlib.machinery import SourceFileLoader
ox = SourceFileLoader("orgxray", str(Path.home() / ".local/bin/orgxray")).load_module()

fails = []
def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond: fails.append(name)

# --- 1. secret_in_head: absolut sti -> repo-relativ, LIVE/HIST ---
with tempfile.TemporaryDirectory() as td:
    repo = Path(td) / "repo"; repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo)
    (repo / "cfg.py").write_text('KEY = "SUPERSECRET123"\n')
    subprocess.run(["git", "add", "."], cwd=repo)
    subprocess.run(["git", "commit", "-qm", "x"], cwd=repo)
    f = {"Secret": "SUPERSECRET123", "File": str(repo / "cfg.py")}
    check("secret_in_head LIVE (absolutt sti)", ox.secret_in_head(repo, f) == "LIVE")
    (repo / "cfg.py").write_text('KEY = "rotert"\n')
    subprocess.run(["git", "add", "."], cwd=repo)
    subprocess.run(["git", "commit", "-qm", "y"], cwd=repo)
    check("secret_in_head HIST etter rotasjon", ox.secret_in_head(repo, f) == "HIST")
    check("secret_in_head manglende fil", ox.secret_in_head(repo, {"Secret": "x", "File": str(repo / "nei.py")}) == "HIST")

# --- 2. triage quality: low-value filter ut, high-value booster ---
raw = [
    {"RuleID": "jwt", "File": "/x/app/android/app/google-services.json", "Secret": "a"*30},
    {"RuleID": "private-key", "File": "/x/repo/.env", "Secret": "-----BEGIN PRIVATE KEY-----"},
    {"RuleID": "private-key", "File": "/x/repo/AuthKey_EUMUT56HAG.p8", "Secret": "k"*40},
    {"RuleID": "aws-access-token", "File": "/x/repo/src/app.js", "Secret": "AKIA" + "1"*16},
]
kept = ox.triage_findings(raw)
paths = {f["File"] for f in kept}
check("google-services.json filtrert (low-quality)", not any("google-services" in p for p in paths))
check(".env beholdt som high", any(p.endswith(".env") for p in kept for p in [p] for f in kept if f["File"] == p) or any(f["_quality"] == "high" for f in kept if f["File"].endswith(".env")))
check("AuthKey.p8 high-quality", any(f.get("_quality") == "high" for f in kept if "AuthKey" in f["File"]))
check("vanlig src-filsti medium", any(f.get("_quality") == "medium" for f in kept if "app.js" in f["File"]))

# --- 3. scope-gate ---
with tempfile.TemporaryDirectory() as td:
    old = ox.SCOPE_FILE
    ox.SCOPE_FILE = Path(td) / "scope.yaml"
    try:
        ox.SCOPE_FILE.write_text("allowed_orgs: [supabase, PostHog]\nforbidden_orgs: [politiet]\n")
        check("scope: tillatt org", ox.check_scope("supabase") is True)
        check("scope: case-insensitive", ox.check_scope("POSTHOG") is True)
        check("scope: ukjent org avvist", ox.check_scope("evilcorp") is False)
        check("scope: forbidden avvist", ox.check_scope("politiet") is False)
        ox.SCOPE_FILE.write_text("allowed_orgs: '*'\nforbidden_orgs: []\n")
        check("scope: wildcard", ox.check_scope("hvem-som-helst") is True)
    finally:
        ox.SCOPE_FILE = old

# --- 4. Kryss-motor-merge: primærlabel på score, ikke motor-base ---
with tempfile.TemporaryDirectory() as td:
    repo = Path(td) / "repo"; repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo)
    sec = "eyJhbGciOiJIUzI1NiJ9." + "A" * 60 + "." + "B" * 40
    (repo / "config.js").write_text(f'const K = "{sec}";\n')
    subprocess.run(["git", "add", "."], cwd=repo)
    subprocess.run(["git", "commit", "-qm", "x"], cwd=repo)
    merged = ox.classify_findings([
        {"RuleID": "aws-access-token", "File": "config.js", "Secret": sec,
         "Match": sec[:80], "StartLine": 1},
        {"RuleID": "jwt", "File": "config.js", "Secret": sec,
         "Match": sec[:80], "_deep": True, "StartLine": 1},
    ], "o", "r", repo_dir=repo)
    check("kryss-motor-merge: én rad", len(merged) == 1)
    m = merged[0]
    # jwt og aws-access-token har samme basis-score (begge i SECRET_RULES)
    # — ved uavgjort vinner deep-motorens mer spesifikke label.
    check("primærlabel = dyp regel ved uavgjort", m["RuleID"] == "jwt")
    check("gitleaks-regel i _alt_rules", m.get("_alt_rules") == ["aws-access-token"])
    check("begge motorer i _engines",
          set(m.get("_engines", [])) == {"gitleaks", "deep"})
    # whitespace-normalisering: «a  b» og «a b» er samme id, «ab» er ikke
    check("whitespace kollapses, ikke slettes",
          ox._secret_id("a  b") == ox._secret_id("a b")
          and ox._secret_id("a b") != ox._secret_id("ab"))

# --- 5. BPE token-efficiency: norsk ordliste + fail-open logging ---
if ox._bpe() is not None:
    # Enkle norske ord fanges av ordlista (sommer er topp-2500)
    check("norsk enkeltord fcaket (sommer2024)",
          ox.fails_token_efficiency("sommer2024") is True)
    # Sammensatte norske ord: morfem-tiling fanger dem, men compounds
    # er den VANLIGSTE norske passordformen — demotes til low i
    # finding_quality, aldri forkastes (samme semantikk som passfrase)
    check("norsk compound beholdt+demotes (fjellby)",
          ox.fails_token_efficiency("fjellby") is False
          and ox._compound_wordlike("fjellby") is True)
    check("norsk compound+år beholdt (lillehamar2024)",
          ox.fails_token_efficiency("lillehamar2024") is False)
    check("norsk compound demotes til low i quality",
          ox.finding_quality({"RuleID": "generic-api-key",
                              "Secret": "fjellby",
                              "File": "x.env", "Entropy": 3.0}) == "low")
    check("norsk compound rest-gap (vardøguv)",
          ox.fails_token_efficiency("vardøguv") is False)
    # Ekte secrets beholdes
    check("provider-secret beholdt (ghp_)",
          ox.fails_token_efficiency("ghp_xK7mP9qL2wR5nT3vJ8fY") is False)
    check("høy-entropi beholdt",
          ox.fails_token_efficiency("xA9fP2qL0sRwZx8") is False)
    # ordbok-passfrase (>=3 hele ord) er en BEVISST valgt hemmelighet:
    # dempes til low i finding_quality, men skal aldri fcakes vekk.
    check("passfrase ikke fcaket (demotes i quality)",
          ox.fails_token_efficiency("correcthorsebatterystaple") is False)
    check("passfrase gjenkjent",
          ox._passphrase_like("correcthorsebatterystaple") is True)
    check("passfrase demotes til low i quality",
          ox.finding_quality({"RuleID": "generic-api-key",
                              "Secret": "correcthorsebatterystaple",
                              "File": "x.env", "Entropy": 3.5}) == "low")
    # ordfilteret krever dominerende dekning: «secret» i sb_secret_ er
    # format, ikke prosa — verifisert mot LIVE/DEAD-korpus (sb_secret_
    # stod i listen over reelle nøkler og ble feilaktig fcaket før
    # den strukturelle dekning-fiksen).
    check("sb_secret_ beholdt (inneholder 'secret')",
          ox.fails_token_efficiency("sb_secret_aip7dIpBP78FQoGz0Hv9") is False)
    check("sbp_ beholdt",
          ox.fails_token_efficiency("sbp_d44558b32c145450158d71bac3") is False)
    # strukturell dekning, ikke prefiksliste: ukjente leverandørformater
    # med secret_/token_ i navnet-overlever likevel
    check("fremmed vendor secret_ beholdt",
          ox.fails_token_efficiency("acme_secret_Zx9QwErTyUiOp1234") is False)
    check("ord-inne-i-token gir ikke compound-fcake",
          ox._compound_wordlike("sb_secret_aip7dIpBP78FQoGz0Hv9") is False)
# fail-open: tokenizer borte -> filter AV, presis én stderr-linje
sub = subprocess.run(
    [sys.executable, "-c", """
import sys, importlib.machinery, importlib.util, io, contextlib
sys.modules['tiktoken'] = None
l = importlib.machinery.SourceFileLoader('ox', '/home/sondre/.local/bin/orgxray')
s = importlib.util.spec_from_loader('ox', l); ox = importlib.util.module_from_spec(s)
sys.argv = ['orgxray']
err = io.StringIO()
with contextlib.redirect_stderr(err):
    l.exec_module(ox)
    ox.fails_token_efficiency('abc123')
    ox.fails_token_efficiency('def456')
lines = [x for x in err.getvalue().splitlines() if 'bpe' in x]
print(len(lines))
"""], capture_output=True, text=True)
check("tokenizer-nedlasting: filter av + én logglinje",
      sub.stdout.strip() == "1")

# --- 6. Prefilter: subject-linje, ikke body; OR-semantikk ---
check("prefilter: dep-bump i subject skippes",
      ox.prefilter_skip("dev", "bump lodash from 1.0.0 to 1.0.1") is True)
check("prefilter: bot-forfatter skippes",
      ox.prefilter_skip("dependabot[bot]", "anything") is True)
check("prefilter: merge-mønster i BODY skippes ikke",
      ox.prefilter_skip("dev", "fix config\n\nmerge pull request #12") is False)
check("prefilter: langt subject over 300 tegn under-skipper (trygt)",
      ox.prefilter_skip("dev", "x" * 400 + "\nbump a from 1 to 2") is False)

# --- 7. Apple .p8 score-paritet: key-id kilde skal ikke telle ---
with tempfile.TemporaryDirectory() as td:
    repo = Path(td)
    (repo / "AuthKey_EUMUT56HAG.p8").write_text("k" * 40)
    (repo / "auth.p8").write_text('key_id: "EUMUT56HAG"\n' + "k" * 40)
    (repo / "bar.p8").write_text("k" * 40)
    fs = [
        {"RuleID": "private-key", "File": str(repo / "AuthKey_EUMUT56HAG.p8"),
         "Secret": "k" * 40, "StartLine": 1},
        {"RuleID": "private-key", "File": str(repo / "auth.p8"),
         "Secret": "k" * 40, "StartLine": 2},
        {"RuleID": "private-key", "File": str(repo / "bar.p8"),
         "Secret": "k" * 40, "StartLine": 1},
    ]
    ox._assemble_components(fs, str(repo))
    q = [ox.finding_quality(f) for f in fs]
    check("p8: AuthKey_ (id i filnavn) = high", q[0] == "high")
    check("p8: auth.p8 + key_id = high (paritet)", q[1] == "high")
    check("p8: bar.p8 uten id = low (component_gap)", q[2] == "low")
    check("p8: komponent eksponert",
          fs[1].get("_components", {}).get("apple-key-id", {}).get("secret") == "EUMUT56HAG")

print(f"\n{'ALLE OK' if not fails else 'FEIL: ' + ', '.join(fails)}")
sys.exit(1 if fails else 0)
