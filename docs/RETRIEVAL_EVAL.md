# Retrieval evaluation

This measures search. It asks how high each method ranks the ATT&CK technique the answer key names, given text an analyst could search with. No language model runs, so it says nothing about verdict accuracy or about whether an agent investigates better with search.

Three methods were compared: BM25 (lexical), dense vectors in Qdrant from `bge-small-en-v1.5` (384 dimensions, through `fastembed` on CPU), and the two fused by reciprocal rank. On the headline query the three cannot be told apart.

## Setup

- Corpus: the 697 current enterprise techniques in ATT&CK v19.2. The catalog is not committed. It sits in the gitignored `datasets/raw/` beside a revision file that pins the version.
- Cases: the 20 dev scenarios. Seventeen have at least one gold technique the corpus can return, so seventeen are scored. Each has one or two.
- Test split: never loaded. `load_dev_cases` does not open a test scenario, and `evaluate` refuses one it is handed. A coverage check read the test split's gold ids once, to see whether they exist in the catalog (one does not, see below). Nothing was tuned or scored on them.
- Queries are built from what the analyst sees (`Scenario.public()`), never from the answer key. Four variants: `alert` (rule title plus the Sigma rule's description), `cmdline` (the trigger event's command line, image and parent), `window` (the command lines of every process created in the window, capped at 1,500 characters), and `alert+cmdline`. Technique ids are scrubbed from every query and Sigma tags are never used.
- Metrics: hit@k (a right technique in the top k), recall@k, and MRR. Intervals are 95% bootstrap intervals over scenarios, 2,000 resamples, fixed seed. Differences between methods are paired, since every method answered the same scenarios.
- The headline, `alert+cmdline` at k=5 with recall@5 and MRR, was fixed in `bench.py` before the first run. The other variants are reported beside it.
- Fusion uses reciprocal rank with the paper's constant of 60 and a candidate pool of 50 per channel. Neither was tuned.

## Results

| Query | Method | hit@5 | recall@5 | MRR |
|---|---|---|---|---|
| alert+cmdline (headline) | lexical | 0.71 (0.47 to 0.88) | 0.53 (0.35 to 0.71) | 0.63 (0.42 to 0.83) |
| alert+cmdline (headline) | dense | 0.71 (0.47 to 0.88) | 0.47 (0.29 to 0.65) | 0.67 (0.43 to 0.88) |
| alert+cmdline (headline) | hybrid | 0.71 (0.47 to 0.88) | 0.53 (0.35 to 0.71) | 0.69 (0.47 to 0.88) |
| alert | lexical | 0.65 (0.41 to 0.88) | 0.44 (0.26 to 0.62) | 0.49 (0.27 to 0.71) |
| alert | dense | 0.71 (0.47 to 0.88) | 0.47 (0.29 to 0.65) | 0.66 (0.43 to 0.88) |
| alert | hybrid | 0.65 (0.41 to 0.88) | 0.44 (0.26 to 0.62) | 0.65 (0.41 to 0.88) |
| cmdline | lexical | 0.59 (0.35 to 0.82) | 0.35 (0.21 to 0.53) | 0.47 (0.27 to 0.69) |
| cmdline | dense | 0.53 (0.29 to 0.76) | 0.38 (0.21 to 0.59) | 0.54 (0.30 to 0.77) |
| cmdline | hybrid | 0.65 (0.41 to 0.88) | 0.44 (0.26 to 0.62) | 0.57 (0.34 to 0.79) |
| window | lexical | 0.47 (0.24 to 0.71) | 0.29 (0.15 to 0.47) | 0.43 (0.21 to 0.66) |
| window | dense | 0.41 (0.18 to 0.65) | 0.26 (0.12 to 0.44) | 0.42 (0.18 to 0.65) |
| window | hybrid | 0.47 (0.24 to 0.71) | 0.29 (0.15 to 0.47) | 0.43 (0.21 to 0.66) |
| random ranking | none | 0.012 | 0.007 | 0.015 |

Every method is far above a random ranking, which manages 1.2% at k=5 over 697 techniques. On the headline query each puts a right technique in the top five for 12 of 17 scenarios.

### The headline comparison

| Difference from lexical | recall@5 | MRR |
|---|---|---|
| dense | -0.06 (-0.18 to +0.06) | +0.03 (-0.11 to +0.19) |
| hybrid | 0.00 (-0.09 to +0.09) | +0.05 (-0.06 to +0.21) |

Every interval contains zero. This is a null result: on 17 scenarios, neither the dense channel nor the fusion is distinguishable from BM25 on the pre-registered headline.

The per-scenario picture agrees. On the headline query 13 of 17 scenarios rank the first right technique identically under all three methods. Four differ:

| Scenario | lexical | dense | hybrid |
|---|---|---|---|
| `otrf_psh_python_webserver` | 6 | 1 | 1 |
| `otrf_psh_powershell_httplistener` | 3 | 1 | 1 |
| `otrf_covenant_installutil` | 1 | 3 | 2 |
| `otrf_cmd_bitsadmin_download_psh_script` | 4 | not in top 20 | 6 |

Dense and hybrid each win two and lose two against lexical.

### An exploratory signal, not a finding

Two of the sixteen paired intervals in the full comparison exclude zero: dense and hybrid MRR on the `alert` variant, up by about 0.17 and 0.16. That variant was not the headline, no correction was applied for making sixteen comparisons, and about one interval in sixteen would exclude zero by chance. Treat it as a reason to look again with more scenarios, not as a result.

Seventeen scenarios cannot support finer claims than these, and the intervals say so. Full per-scenario ranks are in [`experiments/retrieval-dev.json`](experiments/retrieval-dev.json).

Search works best when a binary named in the command line stands for the technique. `mshta`, `regsvr32` and `installutil` scenarios rank their technique first or near it under every method.

## Where it fails

Four scenarios are not found in the top twenty by any method, and neither the dense channel nor the fusion rescued one of them.

- `otrf_cmd_dumping_ntds_dit_file_ntdsutil` and `otrf_wmic_remote_xsl_jscript`: the alert's trigger event is an unrelated process (`cmd.exe` and `RuntimeBroker.exe`), so the query never mentions the behavior. A retriever cannot rank a technique the query does not describe, and the result agrees: the dense model did not recover them either. Building the query from a better event is the lever here.
- `otrf_cmd_psexec_lsa_secrets_dump`: BM25 ranks T1003.004 (LSA Secrets) first, which fits the command line (`reg save HKLM\security\policy\secrets`). The key lists T1003.001 (LSASS Memory) and T1021.002, which rank far down. Search found a technique that matches the command but is not in the key. I did not judge which is right.
- `otrf_cmd_disable_eventlog_service_startuptype_modification_via_registry`: T1112 is not in the top twenty under any method. I did not diagnose it.

The dense channel did move `otrf_psh_python_webserver` from sixth to first and `otrf_psh_powershell_httplistener` from third to first. In both it ranked T1059.001 (PowerShell) first, and in both the alert is the encoded-PowerShell rule. BM25 put Netsh Helper DLL and Scheduled Task first for the same queries. That is consistent with the dense channel matching the alert's meaning where BM25 matched stray words, but two scenarios do not establish it.

## Problems found while building this

The vendored 30 techniques flatter every method. The agent ships with 30 techniques, and they were chosen around the answer key: 16 of them are dev gold ids. Against the dev answer key a random top-5 hits 26.8% of the time over those 30 and 1.2% over the full 697. Any method looks about twenty times better than it is on the small set, so `bench` refuses a corpus under 300 techniques. An earlier draft of this analysis said 98%. That figure came from using the union of all dev gold ids instead of each scenario's own one or two, and the tests now assert the measured numbers.

Technique ids sit in the telemetry. OTRF's Atomic Red Team captures put them in URLs and paths: the bitsadmin scenario's command line downloads `.../atomics/T1197/T1197.md`. In 5 of the 20 dev scenarios the raw telemetry contains a gold id. Queries scrub them, and the four mshta scenarios still rank first without the id. An agent reading those command lines can see the answer directly. I did not check whether the test split has the same property, because it is frozen. The recorded N=13 metrics do not score techniques directly, so what this does to them is unknown.

The answer key names a technique ATT&CK v19.2 does not have. T1562.002 appears in the gold for both splits and is absent from the pinned catalog, so no retriever can return it. It is excluded from scoring and listed under `unreachable_gold` in the result file. The key may predate a renumbering. It is worth checking against the dataset's source.

## What this does not tell you

- Whether search improves an agent's investigation. That needs a model, and the `search_attack_techniques` tool is off by default for that reason.
- Whether a different embedding model, a tuned fusion, or a better query builder would separate the methods. One small model and untuned fusion were tried.
- Which method the API should default to. It uses hybrid when a dense channel is configured. That choice predates this run, and the run gives no reason to change it or to keep it.
- Qdrant in server mode. The client accepts a URL, but there is no Docker on the development machine, so only the in-memory and embedded modes are tested.
- Anything on the test split.

## Reproduce

```bash
uv sync --group retrieval
uv run python -m alert2attack.retrieval.bench --embedder fastembed --out docs/experiments/retrieval-dev.json
```

The first run downloads `BAAI/bge-small-en-v1.5` (about 64 MB) into `datasets/raw/embedder_cache`, which is gitignored. The whole run took 24 seconds including that download. Use `--embedder none` for the lexical baseline alone, which needs no download.

The catalog is not committed. This run used a copy from the sibling CVE-to-ATT&CK repo, which builds it from MITRE's `attack-stix-data` (v19.2) with `python -m evals.golden.build_attack_catalog`. Put it at `datasets/raw/attack_catalog.json`, or point `ALERT2ATTACK_ATTACK_CATALOG` at it.
