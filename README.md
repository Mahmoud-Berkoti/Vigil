# Vigil — BGP Route Monitor & Anomaly Detector

Vigil ingests BGP updates (archived MRT dumps, live RIPE RIS feeds), maintains a
live routing table view (RIB), and detects anomalies: prefix hijacks, sub-prefix
hijacks, route leaks, RPKI-invalid announcements, and update-rate spikes. Alerts
are stored, optionally posted to a webhook, and exposed over a REST API, a web
dashboard, and Prometheus metrics.

> **Safety note:** Vigil is strictly **monitor/receive-only**. It never announces,
> injects, or modifies routes. Live data comes from public collectors (RIPE RIS,
> RouteViews) that exist for exactly this purpose. If you ever peer it live with a
> real BGP speaker, only peer with a collector/route-server that expects a
> monitor-only session, or a local FRR/GoBGP instance you control.

## Architecture

```
   feeds                       +----------------------------------+
   -----                       |              Vigil               |
   RIPE RIS Live (http) --+    |                                  |
   RouteViews/RIS MRT ----+--->|  Ingest Adapters                 |
   files                       |     | (normalize to UpdateEvent)  |
                                |     v                            |
                                |  RIB (per-peer + best view)      |
                                |     |                            |
                                |  Detection Engine                |
                                |   - origin/hijack                |
                                |   - sub-prefix                   |
   REST API (:8080) <-----------|   - route leak (valley-free-ish) |
   Dashboard                   |   - RPKI validation              |
   Prometheus /metrics <--------|   - rate/flap spikes             |
                                |     |                            |
                                |  Alert Store (SQLite) + Notifier |
                                +----------------------------------+
```

Every ingest source normalizes into a common `vg_event_t` (announce/withdraw,
prefix, AS path, origin, next hop, communities, timestamp, peer) — detectors
never care where data came from. The RIB is a per-peer Adj-RIB-In plus a
binary trie per address family for more-specific/covering-prefix queries.
Detectors are independent modules run against each event; "expected origin"
comes from a config watchlist and/or a learned baseline observation window.

## Language & dependencies

Vigil is written in **C (C11)** using only libraries that ship with macOS/Linux:

- `libcurl` — RIS Live streaming + alert webhooks
- `libsqlite3` — alert history store
- POSIX threads/sockets — the HTTP API server and ingest pipeline

No third-party source dependencies; the BGP/MRT wire parsers, JSON parser, and
HTTP server are implemented in this repository (that's the point of the project).

## Build & run

```sh
make            # builds ./vigil
make test       # builds and runs all unit/scenario tests (12 suites)
make fuzz       # ASan/UBSan fuzz run of the BGP parser
make demo       # scripted hijack scenario -> alert visible via the API
```

Serve mode (API + dashboard + Prometheus + ingest) reads a config file:

```sh
./vigil -c vigil.conf
```

See `vigil.conf.example`-style keys in `src/core/config.h`: `api_port`,
`mrt_file` (archive replay) or `rislive_enabled` (live feed), `vrp_file`
(RPKI), `alert_db`, `webhook_url`, `watch = PREFIX [ASN]` (repeatable),
`baseline_window`, `spike_window`/`spike_factor`, `rel_provider`/`rel_peer`
(AS relationships for leak detection).

Other entry points:

```sh
./vigil -r archive.mrt [-q PREFIX]   # one-shot replay stats + optional query
./vigil rov vrp.json PREFIX ASN      # classify one route (RFC 6811)
```

Dashboard: `http://localhost:8080/` · REST: `GET /api/v1/prefixes/{p}`,
`GET /api/v1/asns/{asn}/prefixes`, `GET /api/v1/alerts?type=&prefix=&since=&limit=`,
`GET /api/v1/stats` · Metrics: `GET /metrics` (Prometheus text format).

## Data sources (all public, receive-only)

- **RIPE RIS Live** (`ris-live.ripe.net`) — real-time BGP updates over an HTTP
  NDJSON stream, no auth required, reasonable rate for a single monitor client.
- **RouteViews / RIPE RIS MRT archives** — historical dumps for replay and
  cross-validation (`data.ris.ripe.net/rrcNN/YYYY.MM/updates.*.gz`).
- **RPKI VRP dumps** — a public validator's JSON export (Routinator,
  `rpki-client`, or Cloudflare's `rpki.cloudflare.com/rpki.json`).
- **bgp.tools / RIPEstat** — used during development to spot-check origins and
  RPKI classifications against independent sources.

## Cross-validation & correctness evidence

- `make crosscheck` compares MRT replay counts (updates, announces, withdraws,
  unique prefixes/origins) against `mrtparse` — verified exact match on a real
  142,977-record RIPE RIS dump (`tools/crosscheck.py`).
- `tools/rpki_crosscheck.py` compares RFC 6811 classifications against the
  RIPEstat rpki-validation API — verified on real sampled routes plus the
  RIPE always-invalid beacon prefix.
- The BGP UPDATE parser is exercised by a deterministic fuzz driver
  (`make fuzz`, ASan+UBSan) seeded from its own serializer with random
  mutation and truncation; 500k+ iterations panic-free.
- Detector scenario tests assert each anomaly type fires exactly once on its
  synthetic incident and never on clean traffic, and a real-world MRT replay
  produces zero hijack/sub-prefix/leak/RPKI-invalid alerts with no
  watchlist/relationships configured.

## Status

Built phase by phase per `Vigil.md` (the project spec), each phase committed
separately with its own acceptance evidence:

- [x] Phase 0 — skeleton & data model (prefix/AS-path/event/alert types, config, stub pipeline)
- [x] Phase 1 — BGP UPDATE wire parser (RFC 4271/4760/6793, fuzzed with ASan/UBSan)
- [x] Phase 2 — MRT archive ingestion (TABLE_DUMP_V2 + BGP4MP, cross-validated against mrtparse on a real 142k-record RIS dump)
- [x] Phase 3 — RIB (per-peer Adj-RIB-In, trie queries, history; origin spot-checked against bgp.tools)
- [x] Phase 4 — RIPE RIS Live ingestion (libcurl HTTP stream, ~2k ev/s live, reconnect + backoff; opt-in)
- [x] Phase 5 — detection engine (origin/sub-prefix hijack, valley-free leak heuristic, spike/flap; zero false positives on clean + real traffic)
- [x] Phase 6 — RPKI origin validation (RFC 6811 + AS0/maxLength; 971k real VRPs, cross-checked vs RIPEstat)
- [x] Phase 7 — alerts (SQLite + webhook), REST API, dashboard, Prometheus metrics, `make demo`, CI

## Testing strategy

- **Unit:** BGP/MRT parsers against captured hex fixtures and a real RIS dump;
  native-style fuzzing on the UPDATE parser (ASan/UBSan, never panics); RIB
  operations; RPKI RFC 6811 semantics; each detector against crafted scenarios;
  JSON parser against malformed/adversarial input; HTTP API against a live
  server via a raw-socket test client.
- **Cross-validation:** replay counts vs `mrtparse`; RPKI classifications vs
  RIPEstat.
- **Scenario tests:** synthetic hijack/leak/subprefix/flap fixtures assert
  exactly the expected alert and zero false positives on clean traffic.
- **Live smoke test (opt-in):** `VIGIL_LIVE_TEST=1 ./build/tests/test_rislive`
  connects to RIS Live and asserts events flow with no crashes.
- **CI:** GitHub Actions builds, runs all tests, a short fuzz pass, cppcheck,
  the opt-in live smoke test, and the scripted demo.
