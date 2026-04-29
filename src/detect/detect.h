/*
 * Detection engine. Each normalized event is applied to the RIB and
 * then run through independent detectors:
 *
 *   hijack    — origin differs from the expected origin set (config
 *               watchlist and/or origins learned during the baseline
 *               observation window)
 *   subprefix — a more-specific of a known prefix appears with a
 *               different origin than the covering prefix's expected set
 *   leak      — valley-free violation over configured AS relationships
 *               (heuristic and explicitly approximate: only edges with
 *               known relationships are judged)
 *   spike     — per-prefix / per-peer update-rate bursts and flapping
 *               over a rolling window
 *   rpki      — RFC 6811 origin validation (wired in via vg_rpki_t;
 *               NULL disables it)
 *
 * Time comes from event timestamps, not the wall clock, so MRT
 * replays of historical incidents behave identically to live feeds.
 */
#ifndef VIGIL_DETECT_H
#define VIGIL_DETECT_H

#include "../core/config.h"
#include "../rib/rib.h"
#include "../vigil.h"

typedef struct vg_rpki vg_rpki_t; /* phase 6 */

typedef struct {
    uint64_t events;
    uint64_t alerts[5]; /* by vg_alert_type_t */
    uint64_t suppressed; /* dropped by per-key cooldown */
} vg_engine_stats_t;

typedef struct vg_engine vg_engine_t;

vg_engine_t *vg_engine_new(const vg_config_t *cfg, vg_rib_t *rib,
                           vg_alert_sink_fn sink, void *user);
void vg_engine_free(vg_engine_t *e);
void vg_engine_set_rpki(vg_engine_t *e, vg_rpki_t *rpki);

/* Process one event (applies it to the RIB first). */
void vg_engine_event(vg_engine_t *e, const vg_event_t *ev);
/* vg_event_sink_fn adapter (user = vg_engine_t*) */
void vg_engine_sink(const vg_event_t *ev, void *user);

void vg_engine_stats(vg_engine_t *e, vg_engine_stats_t *out);

/* ---- baseline (exposed for detectors/tests) ----------------------- */

#define VG_BASELINE_MAX_ORIGINS 4

typedef struct {
    uint32_t origins[VG_BASELINE_MAX_ORIGINS];
    int      n_origins;
    double   first_seen;
    bool     locked;  /* observation window elapsed (or configured) */
    bool     watched; /* came from the config watchlist */
} vg_baseline_entry_t;

/* Returns NULL if the prefix has never been observed. */
const vg_baseline_entry_t *vg_engine_baseline(vg_engine_t *e,
                                              const vg_prefix_t *p);

#endif
