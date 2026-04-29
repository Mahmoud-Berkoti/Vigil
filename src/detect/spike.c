/*
 * Update-rate spikes and route flapping, per prefix and per peer.
 *
 * Sliding-window approximation with two fixed buckets: the estimated
 * rate over the last `spike_window` seconds is
 *     cur + prev * overlap_fraction.
 * A spike alerts when that count exceeds
 *     max(spike_min, spike_factor * long_term_rate * window),
 * i.e. bursts must beat both an absolute floor (quiet prefixes) and a
 * multiple of the key's own history (busy prefixes). Event timestamps
 * drive the clock, so replays behave like live traffic.
 */
#include "internal.h"

#include <stdio.h>
#include <string.h>

static bool spike_track(vg_engine_t *e, vg_hashmap_t *map, const void *key,
                        double ts, double *rate_out, uint32_t *count_out) {
    const vg_config_t *cfg = vg_engine_cfg(e);
    double W = cfg->spike_window > 0 ? cfg->spike_window : 60;

    bool created;
    vg_spike_state_t *s = vg_hashmap_upsert(map, key, &created);
    if (!s) return false;
    if (created) {
        s->window_start = ts;
        s->first_ts = ts;
    }

    /* roll buckets forward */
    if (ts - s->window_start >= 2 * W) {
        s->prev = 0;
        s->cur = 0;
        s->window_start = ts;
    } else if (ts - s->window_start >= W) {
        s->prev = s->cur;
        s->cur = 0;
        s->window_start += W;
    }
    s->cur++;
    s->total++;

    double frac = 1.0 - (ts - s->window_start) / W;
    if (frac < 0) frac = 0;
    double windowed = s->cur + s->prev * frac;

    /* Baseline rate from history BEFORE the current window, so a burst
     * can't raise its own threshold. */
    double hist_time = s->window_start - s->first_ts;
    double hist_total = (double)s->total - s->cur;
    double baseline = hist_time > 0 ? hist_total / hist_time : 0;
    double threshold = cfg->spike_factor * baseline * W;
    double floor_ = cfg->spike_min > 0 ? cfg->spike_min : 20;
    if (threshold < floor_) threshold = floor_;

    if (windowed > threshold) {
        *rate_out = windowed / W;
        *count_out = (uint32_t)windowed;
        return true;
    }
    return false;
}

void vg_detect_spike(vg_engine_t *e, const vg_event_t *ev) {
    double rate;
    uint32_t count;

    /* per prefix */
    uint8_t pkey[18];
    pkey[0] = ev->prefix.family;
    pkey[1] = ev->prefix.len;
    memcpy(pkey + 2, ev->prefix.addr, 16);
    if (spike_track(e, vg_engine_spike_map(e, false), pkey, ev->timestamp,
                    &rate, &count)) {
        vg_alert_t a;
        memset(&a, 0, sizeof(a));
        a.type = VG_ALERT_SPIKE;
        a.severity = VG_SEV_INFO;
        a.prefix = ev->prefix;
        a.observed_asn = vg_event_origin(ev);
        char pfx[VG_PREFIX_STRLEN];
        vg_prefix_format(&ev->prefix, pfx, sizeof(pfx));
        snprintf(a.summary, sizeof(a.summary),
                 "update spike for %s: %u updates in window (%.1f/s), "
                 "possible flapping", pfx, count, rate);
        char extra[64];
        snprintf(extra, sizeof(extra), "\"window_count\":%u", count);
        vg_engine_evidence(&a, ev, extra);
        vg_engine_emit(e, &a, ev);
    }

    /* per peer */
    char peer_key[VG_PEER_STRLEN];
    memset(peer_key, 0, sizeof(peer_key));
    memcpy(peer_key, ev->peer, sizeof(peer_key));
    if (spike_track(e, vg_engine_spike_map(e, true), peer_key, ev->timestamp,
                    &rate, &count)) {
        vg_alert_t a;
        memset(&a, 0, sizeof(a));
        a.type = VG_ALERT_SPIKE;
        a.severity = VG_SEV_INFO;
        /* prefix zeroed: this is a peer-level anomaly */
        a.observed_asn = ev->peer_asn;
        snprintf(a.summary, sizeof(a.summary),
                 "update spike from peer %s (AS%u): %u updates in window "
                 "(%.1f/s)", ev->peer, ev->peer_asn, count, rate);
        char extra[64];
        snprintf(extra, sizeof(extra), "\"window_count\":%u", count);
        vg_engine_evidence(&a, ev, extra);
        vg_engine_emit(e, &a, ev);
    }
}
