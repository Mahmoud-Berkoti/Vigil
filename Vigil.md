# Project Spec: BGP Route Monitor & Anomaly Detector ("Vigil")

> **Instructions for Claude Code:** This document is the single source of truth. Build phase by phase, in order, and do not skip ahead. Every phase ends with passing tests, a git commit (Conventional Commits), and updated docs. Write the core in Go. When implementing BGP message parsing, be rigorous about the wire format and edge cases; malformed-update handling is a real-world correctness requirement, not an afterthought. Never fabricate routing data; when live feeds are unavailable, use recorded MRT captures so tests are deterministic. Ask before adding heavy dependencies.

---

## 1. Elevator Pitch

Vigil is a BGP route monitoring and anomaly detection system. It ingests BGP updates, either by establishing a real BGP session with a route collector / route server in monitor-only mode, or by consuming live and archived feeds from public collectors (RIPE RIS Live, RouteViews MRT dumps). It maintains a live view of the routing table (prefixes, AS paths, origins), and detects anomalies: prefix hijacks (unexpected origin AS), route leaks, path changes, sub-prefix hijacks (more-specific announcements), bogon and RPKI-invalid announcements, and update-rate spikes. It exposes alerts and a queryable state via REST + a dashboard.

**Why this matters for Cisco:** Cisco is one of the largest players in service-provider and enterprise routing, and BGP is the backbone protocol their core routing business depends on. Building a tool that speaks BGP at the protocol level, parses real UPDATE messages, and reasons about AS paths and origins demonstrates routing understanding that is rare for an intern and squarely on Cisco's core identity as a routing/switching company.

## 2. Learning Goals (what you must be able to explain afterward)

- The BGP finite state machine (Idle -> Connect -> OpenSent -> OpenConfirm -> Established) and the four message types (OPEN, UPDATE, KEEPALIVE, NOTIFICATION)
- BGP UPDATE structure: withdrawn routes, path attributes (ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF, communities), and NLRI
- eBGP vs iBGP, AS path prepending, and how best-path selection works at a high level
- What a prefix hijack, sub-prefix hijack, and route leak actually are, with real historical examples (e.g., the 2008 YouTube/Pakistan Telecom hijack, various leaks)
- RPKI, ROAs, and Route Origin Validation (valid/invalid/notfound)
- Why BGP has essentially no built-in security and how the industry is retrofitting it (RPKI, ASPA, BGPsec)
- How route collectors (RouteViews, RIPE RIS) work and why they exist

## 3. Tech Stack

| Component | Choice | Rationale |
|---|---|---|
| Language | Go 1.22+ | Networking, concurrency, matches the author's stack |
| BGP session (optional live peering) | Implement OPEN/KEEPALIVE/UPDATE parsing ourselves; optionally interop with a local GoBGP or BIRD/FRR instance as the peer | Parsing UPDATEs by hand is the learning core; a real daemon provides a safe peer |
| Feed ingestion | RIPE RIS Live (websocket JSON) for live, MRT file parsing for archives (RouteViews/RIPE dumps) | Real data without needing to peer with the global table |
| RPKI | Consume a public VRP dump (JSON from an RPKI validator like Routinator's output, or the RIPE RPKI data) | Enables origin validation without running full RPKI crypto |
| Storage | In-memory RIB + optional SQLite/Postgres for alert history and time-series | Simple, queryable |
| API/UI | net/http + chi, small web dashboard | Standard |
| Testing | Go testing + recorded MRT fixtures + synthetic UPDATE generators | Deterministic |
| Observability | Prometheus + structured logs | Standard |

**Environment note:** This project is portable (no special kernel needs). The one caution: do NOT attempt to announce routes or peer with the real global BGP table in a way that injects anything; this is monitor/receive-only. If peering live, peer only with collectors/route servers that expect it, or run a local FRR/GoBGP peer you control. Make this explicit in the README.

## 4. High-Level Architecture

```
   feeds                       +----------------------------------+
   -----                       |              Vigil               |
   RIPE RIS Live (ws) ----+    |                                  |
   RouteViews MRT files --+--->|  Ingest Adapters                 |
   Local FRR/GoBGP peer --+    |     | (normalize to UpdateEvent)  |
                               |     v                            |
                               |  RIB (per-peer + best view)      |
                               |     |                            |
                               |  Detection Engine                |
                               |   - origin/hijack                |
                               |   - sub-prefix                   |
   REST API (:8080) <----------|   - route leak (valley-free-ish) |
   Dashboard                   |   - RPKI validation              |
   Prometheus (:9090) <--------|   - rate/flap spikes             |
                               |     |                            |
                               |  Alert Store + Notifier          |
                               +----------------------------------+
```

Core design decisions:

- **Normalize every source into a common `UpdateEvent`** (announce/withdraw, prefix, AS path, origin, next hop, communities, timestamp, peer). Detectors never care where data came from.
- **The RIB is per-peer** (Adj-RIB-In style) plus a merged view; detectors run on the stream and can query the RIB for context (e.g., "was this prefix previously originated by a different AS?").
- **Detectors are independent modules** implementing a `Detect(event, ribView) []Alert` interface, so adding a new anomaly type is isolated.
- **Ground truth for hijacks comes from a baseline:** a learned or configured map of prefix -> expected origin AS (seeded from RPKI ROAs and/or an observation window), so "unexpected origin" is well defined.

## 5. Repository Layout

```
vigil/
├── cmd/vigil/main.go
├── internal/
│   ├── bgp/                # wire protocol
│   │   ├── message.go      # header + type dispatch
│   │   ├── open.go
│   │   ├── update.go       # withdrawn, path attrs, NLRI
│   │   ├── pathattr.go     # ORIGIN, AS_PATH, NEXT_HOP, MED, communities...
│   │   ├── nlri.go         # prefix encoding (v4 + v6)
│   │   └── fsm.go          # optional live session state machine
│   ├── mrt/                # MRT file parser (TABLE_DUMP_V2, BGP4MP)
│   ├── ingest/
│   │   ├── rislive/        # RIPE RIS Live websocket adapter
│   │   ├── mrtfile/        # archive replay adapter
│   │   └── peer/           # optional live peer (via our fsm or GoBGP)
│   ├── rib/                # routing information base
│   ├── rpki/               # VRP loading + origin validation
│   ├── detect/
│   │   ├── hijack.go
│   │   ├── subprefix.go
│   │   ├── leak.go
│   │   ├── rpki.go
│   │   └── spike.go
│   ├── alert/              # store + notifier (webhook/log)
│   ├── api/
│   └── metrics/
├── data/
│   ├── fixtures/           # recorded MRT snippets + synthetic updates
│   └── vrp/                # sample RPKI VRP dump
├── web/                    # dashboard
├── Makefile
└── README.md
```

## 6. Build Phases

### Phase 0: Project Skeleton and Data Model
- Define the `UpdateEvent`, `Prefix`, `ASPath`, and `Alert` types.
- Set up config (which feeds to enable, which ASNs/prefixes to watch, RPKI source).
- **Acceptance:** `go build` works; a stub ingest adapter emits a hardcoded UpdateEvent that flows through to a logger. Types have thorough table-driven tests for parsing/formatting prefixes (v4 and v6, including edge cases like /0 and /32).

### Phase 1: BGP UPDATE Parser (the core skill)
- Parse the BGP message header (16-byte marker, length, type) and the UPDATE message: withdrawn routes, total path attribute length, path attributes (handle at minimum ORIGIN, AS_PATH with AS_SET/AS_SEQUENCE and 4-byte ASNs, NEXT_HOP, MULTI_EXIT_DISC, LOCAL_PREF, COMMUNITIES, MP_REACH/MP_UNREACH for v6), and NLRI.
- Rigorously handle malformed updates (bad lengths, truncated attributes, unknown attribute types with the optional/transitive flags).
- **Acceptance:** Round-trip and parse tests against real captured UPDATE bytes (extract a few from an MRT dump as hex fixtures). Fuzz the parser (Go native fuzzing) and ensure it never panics on arbitrary input. Correctly decode a 4-byte-ASN AS_PATH and an IPv6 MP_REACH_NLRI update.

### Phase 2: MRT Archive Ingestion
- Parse MRT files (TABLE_DUMP_V2 for RIB snapshots, BGP4MP for update streams) from RouteViews/RIPE archives.
- Replay a downloaded MRT dump through the normalize layer into UpdateEvents at configurable speed.
- **Acceptance:** Given a real MRT dump (checked in as a small fixture, or downloaded by a make target), the tool replays it and reports counts (prefixes, updates, unique origins) that match an independent tool like `bgpdump` or `mrtparse`. This cross-check is the correctness proof.

### Phase 3: RIB Construction
- Build a per-peer Adj-RIB-In: apply announcements and withdrawals, keyed by prefix, storing the full attribute set and timestamp/peer.
- Provide query methods: current origin(s) for a prefix, all prefixes originated by an ASN, more-specifics of a prefix (for sub-prefix detection), history of changes for a prefix.
- **Acceptance:** After replaying an MRT stream, querying a known prefix returns its expected origin AS (spot-check against a public looking glass or bgp.tools for a historical prefix). Withdrawals correctly remove routes. Memory stays bounded on a large replay (report the numbers).

### Phase 4: RIPE RIS Live Ingestion (real-time)
- Connect to the RIPE RIS Live websocket, subscribe to the update stream (optionally filtered by prefix/ASN/host), normalize into UpdateEvents.
- Handle reconnection, backpressure, and the JSON schema robustly.
- **Acceptance:** The tool connects to RIS Live and processes real, live BGP updates from the global table, logging a live rate (updates/sec) and feeding the same RIB and detectors as the archive path. (If network egress is restricted in your environment, document this and rely on MRT replay; make the live path opt-in.)

### Phase 5: Detection Engine
Implement detectors, each with clear definitions and tests using synthetic scenarios:

1. **Origin hijack:** a prefix is announced with an origin AS that differs from its expected origin (from RPKI ROA and/or a learned baseline over an observation window). Alert with old vs new origin.
2. **Sub-prefix hijack:** a more-specific of a monitored prefix appears with a different origin (this is the classic, dangerous case because more-specifics win in forwarding).
3. **Route leak:** detect valley-free violations heuristically (e.g., a route that appears to transit through an AS that should not be providing transit for that pair), using AS-relationship inference or a configured customer/provider set. Keep this heuristic and clearly documented as approximate.
4. **RPKI invalid:** origin validation against loaded VRPs (valid / invalid / notfound); alert on invalids.
5. **Update spikes / flapping:** per-prefix and per-peer update-rate anomalies (sudden bursts, route flap) via a rolling window.

- **Acceptance:** For each detector, a synthetic scenario in fixtures triggers exactly the expected alert and clean traffic triggers none (no false positives on the baseline). Bonus: replay a real historical hijack MRT (e.g., a documented event) and show your tool flags it.

### Phase 6: RPKI Origin Validation
- Load a VRP set (JSON from Routinator/RIPE) into an efficient structure (prefix -> allowed origins + max length).
- Implement RFC 6811 route origin validation semantics (valid/invalid/notfound with maxLength handling).
- **Acceptance:** Given a VRP set and a stream, classifications match a reference validator on a sample set. An announcement violating maxLength is correctly flagged invalid.

### Phase 7: Alerts, API, Dashboard, Observability
- Alert store (SQLite) with severity, type, prefix, ASNs involved, evidence, timestamp; notifier via webhook and structured log.
- REST: `GET /api/v1/prefixes/{p}` (current state + history), `GET /api/v1/asns/{asn}/prefixes`, `GET /api/v1/alerts` (filterable), `GET /api/v1/stats`.
- Dashboard: live alert feed, watched-prefix status, update-rate graphs, top origins.
- Prometheus metrics: updates/sec, alerts by type, RIB size, RIS Live connection health.
- **Acceptance:** End-to-end: replay (or live-consume) a stream, trigger detectors, see alerts surface in the API and dashboard, and Prometheus scrape works. `make demo` runs a scripted hijack scenario from fixtures and shows the alert appearing.

## 7. Testing Strategy

- **Unit:** BGP/MRT parsers against captured hex fixtures; native fuzzing on the UPDATE parser (must never panic); RIB operations; each detector against crafted scenarios.
- **Cross-validation:** replay an MRT dump and compare prefix/origin counts against `bgpdump`/`mrtparse` output.
- **Scenario tests:** synthetic hijack/leak/subprefix/flap fixtures that assert exactly-expected alerts and zero false positives on a clean baseline.
- **Live smoke test (opt-in):** connect to RIS Live, assert updates flow, run for N seconds, assert no crashes.
- **CI:** GitHub Actions builds, runs unit + scenario tests + fuzz (short duration), staticcheck/go vet. Live tests are opt-in / skipped in CI if egress is blocked.

## 8. Data Sources (all public, receive-only)

- RIPE RIS Live: real-time BGP updates over websocket
- RouteViews and RIPE RIS MRT archives: historical dumps for replay and detector validation
- RPKI VRP dumps: from a public validator instance or the RIPE RPKI repository
- bgp.tools / a looking glass: for manual spot-checking origins during development

Document each source, its format, and its rate limits in the README. Re-emphasize: this tool never announces or injects routes.

## 9. Interview Talking Points (study these)

- The BGP FSM and the four message types; what is in an UPDATE and why AS_PATH is the security-relevant attribute.
- What a prefix hijack vs sub-prefix hijack vs route leak is, with a concrete historical example, and why more-specifics are so dangerous.
- Why BGP is insecure by design (path-vector protocol built on trust) and how RPKI/ROV, ASPA, and BGPsec attempt to fix origin and path validation, plus their deployment gaps.
- How route collectors give you a global-ish view without peering with the whole internet, and the difference between what a collector sees and what any single router sees.
- Your detectors: how you defined "expected origin," how you keep false positives down, and the honest limits of heuristic leak detection.
- How this connects to Cisco: their routing platforms implement this protocol, and operators need exactly this kind of monitoring (Cisco Crosswork, BGP monitoring in service-provider networks).

## 10. Resume Bullet Targets

- Built a BGP route monitor in **Go** that parses raw BGP **UPDATE** messages and **MRT** archives and ingests live global routing data via **RIPE RIS Live**, maintaining a per-peer RIB over **[N]k+** prefixes.
- Implemented anomaly detectors for prefix/sub-prefix **hijacks**, **route leaks**, and **RPKI-invalid** announcements (RFC 6811 origin validation), validated against recorded real-world hijack events with zero false positives on a clean baseline.
- Hardened the wire-format parser with Go native **fuzzing** (panic-free on arbitrary input) and cross-validated RIB output against `bgpdump`, wired into **CI**.

*(Fill in [N] from your actual replay. Cross-validated numbers are credible.)*

## 11. Resources

- RFC 4271 (BGP-4), RFC 4760 (MP-BGP for v6), RFC 6811 (Origin Validation), RFC 6396 (MRT format)
- RIPE RIS Live documentation and the RIS Live JSON schema
- RouteViews project (archive layout and access)
- GoBGP and FRR/BIRD docs if you run a local peer
- Cloudflare and RIPE Labs blog posts on famous BGP hijacks and leaks (great narrative material for interviews)
- "BGP" (Iljitsch van Beijnum) or Cisco's BGP design guides for protocol depth
