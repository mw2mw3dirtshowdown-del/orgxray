# OrgXray — operative notater

Lokal-first recon/skanning for autorisert responsible disclosure.
Hovedfil: `~/.local/bin/orgxray` (enkelt Python-executable).
Data: `~/arkiv/org-xray/` (repos, reports, people, rules, runs.jsonl).

## Sikkerhetsmodell (ikke fjern)

- Kloning kjører `git -c core.hooksPath=/dev/null` overalt — ondsinnede
  repos kan shippe hooks; de får aldri eksekvere.
- `git lfs` er IKKE installert på host eller i `orgxray-box`, og ingen
  kode bruker `--recurse-submodules`. Hvis git-lfs noen gang installeres:
  legg til `GIT_LFS_SKIP_SMUDGE=1` i `clone_repo` (smudge-filter er ikke
  en hook og vil ellers kjøre med nett).
- Sandkasse: `~/orgxray-box/bin/orgxray-sandbox` — Docker, `/data`
  read-only, `/work` rw, statiske kommandoer `--network none`,
  bridge kun for clone/API. `ORGXRAY_NET` overstyrer.
- Aldri send noe automatisk — rapporter/pitch er manuelt gate.
- Outbound-verifisering (når den noen gang bygges): KUN les-only
  (f.eks. `GET /v1/apps` for Apple, `select 1` for service-role),
  ALDRI skriving. Autorisasjon dokumenteres per target FØR kallet,
  ikke etter — det er den eneste handlingen som treffer et fremmed
  system.
- Shortlist fryses ved 43 enheter til de er gjennomgått — history-
  passet får ikke utvide arbeidslista før da.

## Budsjett og versjonering

- `ORGXRAY_REPO_BUDGET` default 300s, `ORGXRAY_GITLEAKS_TIMEOUT` 300s.
- `ORGXRAY_STALE_DAYS` default 1095 (3 år) — stale er en TIER, ikke
  gate: repoer uten pushes over terskelen skannes likevel, men
  HEAD-only (grunt klon, `gitleaks dir`, ingen unshallow) og sorteres
  nederst i shortlisten med `[stale X.Xy]`. `_repo_ts` (siste
  commit-timestamp) stemples på hvert triaget funn for validering.
- `RULES_REV` = sha256 av `rules/*.md` kun — kodeendringer endrer den
  ikke. Skrevet som `_rules_rev` på hvert funn.
- `runs.jsonl`: full-scan logger count+hash, quick logger full fil-liste
  + `days` + `files_sha`.

## Dedupe/merge-semantikk

- `_secret_id` = ENKANONISK normaliser (kant-ws trim, indre ws-serier
  kollapset til ett mellomrom, quotes strippet) — begge motorer går
  gjennom den.
- Kryss-motor-duplikat (gitleaks+deep, samme secret+fil, StartLine
  innen 5 linjer) MERGES: gitleaks eier `_status` (LIVE/HIST),
  primærlabel velges på `_rule_base`-score (uavgjort: deep vinner),
  `_alt_rules` + `_engines` beholder provenance.
- Samme secret i samme fil >5 linjer fra hverandre = separate funn.

## Deteksjonsfilosofi (betterleaks-adapsjoner)

- **BPE token-efficiency** (`fails_token_efficiency`, cl100k_base via
  tiktoken): secrets er *sjelden* tekst, ikke bare høy entropi.
  Threshold 2.5 (2.1 for <12 tegn) — kalibrert mot eget korpus:
  alle Q_high-funn (n=7) har TE<2.5, 31 % av Q_low ligger ≥2.5.
  Kasseres i `_match_secrets` for generic-api-key; demotes til low i
  `finding_quality` for ikke-SECRET_RULES. Kilde:
  aikido.dev «Rare Not Random».
  - **Norsk-lag**: cl100k_base er engelsk-tunet — norske ord gir
    lavere TE og ser «sjelden» ut. `_COMMON_WORDS_NO` = topp-2500
    norske frekvensord + `_NO_MORPHEMES_B85` = topp-10000 morfemer
    for **sammensetnings-tiling** (`_compound_wordlike`, DP over
    alfabetisk del — `fjellby`=fjell+by, `lillehamar2024`,
    `bergensregnet` fcakes). Målt: 15/18 norske fcake-eksempler
    filtreres (før: 3/18). **Rest-gap**: propne stedsnavn og
    compounds som ikke fliser (vardøguv) — dokumentert, ikke
    feilsøkt videre.
  - **Strukturell ordfilter** (`_wordlike`): ordfilteret fyre
    bare når ordbokord dekker ≥60 % av *alfabetisk innhold*
    (ikke delstreng-match). `sb_secret_…` overlever fordi
    «secret» er 6 av ~19 alfa-tegn; ren prosa
    (`the quick brown fox`, `password123`) fcakes. Ingen
    prefiksliste — fremmede leverandørformater med
    `secret_`/`token_`/`key_` dekkes automatisk.
    `_compound_wordlike` krever i tillegg ≥2 morfem-segmenter
    og hopper over rene ordbokord — ett vilkårlig
    morfem-treff i et provider-prefiks teller ikke som
    compound.
  - **Ordbok-passfrase** (`_passphrase_like`): en alfabetisk
    kjernedel (6–128 tegn) som flises *fullstendig* av ≥3
    hele ordbokord (`_EN_WORDS_B85` = engelsk topp-20 000 +
    `_COMMON_WORDS` EN/NO, segmenter 3–20 tegn) er en bevisst
    valgt passfrase — **ekte secret, men svak**: den returnerer
    *ikke* fail i `fails_token_efficiency` og demotes til
    `low` i `finding_quality`. Aldri forkastet. Skillet mot
    sammensetninger: passfraser teller *hele ord*, compounds
    teller *morfemer* — `fjellby` (2 morfemer) demotes,
    `correcthorsebatterystaple` (4 ord) demotes, begge som low.
  - **Sammensetninger demotes, ikke forkastes**: compounds er
    den vanligste norske passordformen — `_compound_wordlike`
    returnerer *ikke* fail i `fails_token_efficiency` og
    demotes til `low` i `finding_quality` (samme semantikk som
    passfraser). Bare `_wordlike` (dominerende ordbok-dekning
    = prosa) forkaster i ordbok-laget. `sommer2024` fcakes
    fortsatt via `_wordlike`; `fjellby`/`lillehamar2024`/
    `sommerfisketur2024` overlever som low.
  - **DP-tak**: `_COMPOUND_MAX_RUN=45`, `_PASSPHRASE_MAX_RUN=128`
    — alfabetiske runs lengre enn taket avgjøres av TE-laget,
    ikke ordboksflis. Målt: 3.2 KB PEM-input ≈1.6 ms/kall
    (alle tre sjekker), 4000-tegns alfa-run ≈0.6 ms/kall —
    taket holder, ingen kvadratisk atferd.
  - **Kalibrering — kurve, ikke punkt** (4 952 unike generiske
    funn, 4565 rapportfiler): ord-laget (`_wordlike`) forkaster
    62 (1.3 %); passfraser (47) + compounds (124) demotes til
    low (3.5 %). På TE-kandidatene: terskel 2.0 → 693 fcaket
    (14.0 % totalt), 2.2 → 487 (9.8 %), 2.5 → 439 (8.9 %),
    2.8 → 384 (7.8 %). **Samlet effekt ved 2.5: ~10.1 % av
    generiske kandidater fjernes + 3.5 % demotes ≈ 13.6 %
    berørt** — ikke 31 %. Terskelen flytter ~250 funn per
    0.3 steg — valget er etterprøvbart, ikke et hellig tall.
    Histogrammet har en digital «kne» ved ~2.8–3.0 (fra
    17–24/bånd til 47–49/bånd).
  - **Kalibrering — ærlig status**: Q_high/Q_low er delvis
    sirkulære (labels korrelerer med entropi). Ekstern akse:
    8 verifiserte LIVE/DEAD-utfall, TE-målt 1.42–2.00 — **ingen
    observasjoner i 2.0–2.8-sonen**, så ekstern settet kan
    ikke validere selve terskelen, bare at 1.4–2.0 slipper
    gjennom. `sbp_` er DØD med TE 2.00 mens ngrok er LIVE med
    TE 1.44: med n=5+3 er det **umulig** å si at TE forutsier
    levetid — TE er et presisjonsfilter mot falske positiver,
    ikke en liveness-prediktor. Det skal ikke leses som
    «lav TE = levende».
  - **TE 2.5 sannhetsstikkprøve (2026-11-11)**: 20 unike
    generic-api-key-funn under (2.2–2.5) og 20 over
    (2.5–2.8) klassifisert manuelt — **0/40 plausibelt
    ekte**. Begge sider er ~100 % søppel: test-nøkler,
    identifikatorer, env-var-navn med `=`, sjekksummer,
    stedsnavn. Presisjonsproblemet sitter i selve
    generic-regelen (fyrer på ikke-secrets), ikke ved
    TE-kanten. Detaljer: `reports/VERIFIKASJON-20261111.md`.
    Verifiseringsrunde over 37 shortlist-enheter:
    1 LIVE, 5 DØD, 8 uverifiserbare, 23 FP/fixture —
    maskinlesbar logg i `verification-outcomes.jsonl`.
  - **Lisenser**: ordlister/morfemer kommer fra
    `hermitdave/FrequencyWords` (`no_50k`, `en_50k`) —
    **innhold CC BY-SA 4.0**, kode MIT. **SA = ShareAlike**: den
    innebygde listen er *avledet innhold*; ved distribusjon
    av orgxray (binær eller kilde som inneholder lista)
    kan de avledede ord-/morfemlistene være bundet til
    å deles under samme CC BY-SA 4.0-vilkår — ikke bare
    attribusjon. Praktisk konsekvens: en lukket/kommersiell
    distribusjon må sjekke SA-plikt eller licence-bygge
    egen liste. Attribusjon: dette feltet + kommentar over
    `_COMMON_WORDS_NO`/`_NO_MORPHEMES_B85` i orgxray.
  - **Fail-open er logget**: tokenizer som ikke laster → én
    stderr-linje `[orgxray] bpe-tokenizer utilgjengelig …`,
    filteret slås av for prosessen (aldri stille).
  - **Container**: `tiktoken==0.13.0` + prewarmed
    `TIKTOKEN_CACHE_DIR=/opt/tiktoken-cache` er bakt inn i
    `orgxray-box:latest` — påkrevd fordi runtime er
    `--network none`. Verifisert i container.
    **orgxray-binæren KOPIERES ALDRI inn i image**: Dockerfile
    installer en shim på `/usr/local/bin/orgxray` som nekter
    med «mangler bind-mount» hvis orgxray-sandbox ikke har
    mountet levende kode — en COPY'et versjon ville bake inn
    en stille stale-kopi (funn fra utdatert detektor ser
    helt normalt ut). `orgxray-sandbox` bind-mounter
    `~/.local/bin/orgxray` read-only over samme sti.
    **Bygg-stempel**: `[orgxray] build <sha256(__file__)[:12]@dato>`
    skrives til stderr ved start av scan/history/members/
    quick/deep/self, og `build`-feltet legges i hver
    runs.jsonl-rad — en stale kopi er synlig i loggen.
- **Prefilter** (`prefilter_skip`): attribute-sjekk FØR regex —
  forfatter (`renovate[bot]`, `dependabot`, `github-actions` …) ELLER
  **første commit-melding-linje** (subject, trunkert til 300 tegn;
  body-tekst scannes aldri — «merge» i sitert body utløser ikke
  skip). OR-semantikk; lengde alene er aldri skipp-kriterium, og
  mønster etter tegn 300 under-skiper (regex kjører likevel) —
  prefilter-feil kan ikke tape secrets. Path-attributtet dekkes
  av FP_PATH. Ser aldri filinnhold.
- **Components** (`_assemble_components`): multipart-regler —
  `private-key` i `*.p8` krever `apple-key-id` (filnavn
  `AuthKey_<ID>.p8` eller `key_id`/`kid`/`issuer_id` i samme fil).
  Manglende komponent → `_component_gap` → quality low.
  Tilgang: `f["_components"]["apple-key-id"]["secret"]`.

## Verifikasjon

- `python3 ~/orgxray-box/test_orgxray.py` — regresjonstester
  (secret_in_head, triage, scope, merge/label/whitespace).
- `python3 -m py_compile ~/.local/bin/orgxray` etter hver endring.
