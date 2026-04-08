# Vigil — BGP Route Monitor & Anomaly Detector

Vigil ingests BGP updates (archived MRT dumps, live RIPE RIS feeds), maintains a
live routing table view (RIB), and detects anomalies: prefix hijacks, sub-prefix
hijacks, route leaks, RPKI-invalid announcements, and update-rate spikes. Alerts
are exposed over a REST API and a web dashboard.

> **Safety note:** Vigil is strictly **monitor/receive-only**. It never announces,
> injects, or modifies routes. Live data comes from public collectors (RIPE RIS,
> RouteViews) that exist for exactly this purpose.

## Language & dependencies

Vigil is written in **C (C11)** using only libraries that ship with macOS/Linux:

- `libcurl` — RIS Live streaming + alert webhooks
- `libsqlite3` — alert history store
- POSIX threads/sockets — API server and pipeline

No third-party source dependencies; the BGP/MRT wire parsers, JSON handling, and
HTTP server are implemented in this repository (that's the point of the project).

## Build & test

```sh
make          # builds ./vigil
make test     # builds and runs all unit/scenario tests
```

## Status

Built phase by phase per `Vigil.md` (the project spec):

- [x] Phase 0 — skeleton & data model (prefix/AS-path/event/alert types, config, stub pipeline)
- [x] Phase 1 — BGP UPDATE wire parser (RFC 4271/4760/6793, fuzzed with ASan/UBSan)
- [x] Phase 2 — MRT archive ingestion (TABLE_DUMP_V2 + BGP4MP, cross-validated against mrtparse on a real 142k-record RIS dump)
- [x] Phase 3 — RIB (per-peer Adj-RIB-In, trie queries, history; origin spot-checked against bgp.tools)
- [x] Phase 4 — RIPE RIS Live ingestion (libcurl HTTP stream, ~2k ev/s live, reconnect + backoff; opt-in)
- [ ] Phase 5 — detection engine
- [ ] Phase 6 — RPKI origin validation
- [ ] Phase 7 — alerts, API, dashboard, observability
