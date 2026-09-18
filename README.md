# clash-free-auto

Automated maintenance of a **Clash Verge Rev** (Mihomo / Clash Meta) free-node
subscription. Runs on **GitHub Actions** every 6 hours so your Windows box
stays off. No local process, no paid API, no token in the repo.

---

## 1. What this is

A Python pipeline that:

1. fetches public free-node subscription feeds listed in `config/sources.yaml`
2. parses them (Clash / Mihomo YAML, base64 YAML, ss:// vless:// vmess://
   trojan:// hysteria:// link lines, v2ray JSON)
3. normalizes, dedups, structurally validates, TCP-probes a subset, and scores
4. keeps the best ~50–100 nodes
5. generates a Mihomo-compatible `output/clash.yaml`
6. writes `output/status.json` with run diagnostics
7. auto-commits **only if the output actually changed**

Your machine just points Clash Verge Rev at the GitHub Raw URL.

## 2. How it works

```
schedule / dispatch
        ↓
   fetch (requests, 30s timeout, base64-aware)
        ↓
   parse  (Clash/Mihomo YAML · base64 YAML · ss:// vless:// vmess://
           trojan:// hysteria:// links · v2ray JSON)
        ↓
   normalize (clean names, drop broken nodes)
        ↓
   dedup     (key = type + server + port)
        ↓
   validate  (structural + capped TCP probe, never a scanner)
        ↓
   score     (completeness + validation + protocol bonus;
               90-100 excellent / 75-89 good / 60-74 ok / <60 out)
        ↓
   keep top N (max 100; if TCP-confirmed, floor=60; else floor=30)
        ↓
   generate  (Mihomo YAML with SELECT/AUTO/DIRECT groups + CN-direct rules)
        ↓
   status.json (always written; no secrets)
        ↓
   auto-commit if clash.yaml or status.json changed
   else "No changes to commit."
```

Safety floor (`src/main.py`): **if fewer than `MIN_FINAL_NODES` (3) proxies
survive, the pipeline writes `status.json` with `error: "insufficient valid
proxies"` and exits 0 without touching `clash.yaml`.** Old config is preserved.

## 3. Configure the free-node sources

Edit `config/sources.yaml`:

```yaml
sources:
  - name: au1rxx_clash
    url: "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/clash.yaml"
    enabled: true
    type: auto

  - name: chengaopan_automerger
    url: "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.yml"
    enabled: true
    type: auto
```

Rules:
- Only public, legal, accessible subscription URLs. No tokens, passwords, or personal cookies.
- `enabled: false` disables a source without deleting it.
- `type: auto` lets the parser auto-detect format (YAML / base64 / link / JSON).
- If a source 404s, times out, or is base64 that doesn't decode, the run skips
  it and continues. One bad source never breaks the whole run.

## 4. Add a new public source

Append to `config/sources.yaml`:

```yaml
  - name: my_source
    url: "https://yourtrustedhost.example/sub/clash.yaml"
    enabled: true
    type: auto
```

Push the commit. The next scheduled (or manually triggered) Actions run
picks it up automatically.

## 5. GitHub Actions

`update.yml` runs:
- **every 6 hours** on UTC (`cron: "0 */6 * * *"`)
- **on manual dispatch** (click "Run workflow" → "Run")

It:
1. `pip install -r requirements.txt`
2. `python -m src.main` (the pipeline)
3. `python -m pytest -q` (if tests fail, the job fails and no commit is made)
4. `git add output/clash.yaml output/status.json && git commit … && git push`
   — only when the diff is non-empty.

Use the `GITHUB_TOKEN` secret that GitHub provides on every run. No token is
written into the repo or the code.

## 6. Manual run

Repo → **Actions** tab → `auto-update` → **Run workflow** → pick branch →
confirm. Watch the live log in the same tab.

## 7. Reading the run log

Actions → latest run → click the `update` job. You'll see:
- `source <name> -> N raw nodes`
- `normalized / dedup / validated / kept` counts
- `wrote …/clash.yaml with N proxies` or
- `Update skipped: insufficient valid proxies`

## 8. Reading `status.json`

Open `output/status.json` (repo → Actions → latest run → commit, or Raw URL):

```json
{
  "updated_at": "2026-09-18T19:26:27Z",
  "sources_total": 4,
  "sources_success": 4,
  "sources_failed": 0,
  "raw_nodes": 5877,
  "parsed_nodes": 5874,
  "deduplicated_nodes": 4148,
  "validated_nodes": 4148,
  "validated_tcp": 0,
  "final_nodes": 100,
  "scores": [40, 40, 40, …],
  "error": null
}
```

No tokens, no PII. The `error` field will say `insufficient valid proxies`
when a skip happened.

## 9. Raw subscription URL

`https://raw.githubusercontent.com/<YOUR-USER>/clash-free-auto/main/output/clash.yaml`

That's the URL you paste into Clash Verge Rev.

## 10. Add the subscription in Clash Verge Rev

1. Open **Profiles / 配置**
2. Click **+ / 添加** in the upper-right
3. Pick **Remote / 远程** and enter the Raw URL above
4. **Import / 导入**

The profile now appears in your profile list.

## 11. Update the subscription

- **Auto:** GitHub Actions pushes an update every 6 h; Clash Verge Rev's
  "auto-update" toggle on that profile re-pulls it on its own.
- **Manual:** Profiles → pick the profile → **Update / 刷新** icon.

## 12. What if every node dies?

Two safety mechanisms:

- **Pipeline floor** — if fewer than 3 nodes survive, `clash.yaml` is NOT
  overwritten, the previous config stays, and `status.json` says
  `insufficient valid proxies`. Your device keeps the last known-good set.
- **Add a source** — drop a new public feed into `config/sources.yaml`,
  commit, and the next run will pick it up. If the whole ecosystem is dead
  for a day, that's the normal outcome; the system degrades gracefully.

## 13. File layout

```
clash-free-auto/
├── .github/
│   └── workflows/
│       └── update.yml        # schedule + dispatch + auto-commit
├── config/
│   └── sources.yaml          # public feed URLs you control
├── src/
│   ├── __init__.py
│   ├── main.py               # pipeline orchestrator
│   ├── fetch.py              # http fetch with base64 auto-detect
│   ├── parser.py             # Clash/Mihomo YAML · b64 · link · JSON
│   ├── normalize.py          # clean names, canonical fields
│   ├── deduplicate.py        # key = (type, server, port)
│   ├── validator.py          # structural + capped TCP probe
│   ├── scoring.py            # 0-100 score with two floors
│   └── generator.py          # Mihomo YAML with groups/rules/DNS
├── output/
│   ├── clash.yaml            # generated config (raw URL target)
│   └── status.json           # run diagnostics
├── tests/
│   ├── test_parser.py
│   └── test_generator.py
├── requirements.txt
└── README.md
```

## 14. Constraints

- No internet scanning. Only URLs you configure in `sources.yaml`.
- No Docker, no Redis, no DB, no Node, no AI. Just Python + PyYAML +
  GitHub Actions.
- No secrets in the repo. `GITHUB_TOKEN` is an Actions built-in.

## 15. License

MIT.
