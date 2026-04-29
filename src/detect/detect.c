#include "detect.h"

#include "../util/hashmap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

#define ALERT_COOLDOWN 300.0 /* secs (event time) per alert key */

struct vg_engine {
    const vg_config_t *cfg;
    vg_rib_t          *rib;
    vg_rpki_t         *rpki;
    vg_alert_sink_fn   sink;
    void              *user;

    vg_hashmap_t baseline;     /* prefix key(18) -> vg_baseline_entry_t */
    vg_hashmap_t spike_prefix; /* prefix key(18) -> vg_spike_state_t */
    vg_hashmap_t spike_peer;   /* peer key(64)   -> vg_spike_state_t */
    vg_hashmap_t cooldown;     /* alert key(24)  -> double last_ts */
    vg_hashmap_t rels;         /* asn pair(8)    -> uint8 rel type */

    vg_engine_stats_t st;
};

/* ---- keys ---------------------------------------------------------- */

static void prefix_key(const vg_prefix_t *p, uint8_t key[18]) {
    key[0] = p->family;
    key[1] = p->len;
    memcpy(key + 2, p->addr, 16);
}

/* ---- AS relationships (for the leak heuristic) --------------------- */

enum { REL_NONE = 0, REL_P2C = 1, REL_C2P = 2, REL_PEER = 3 };

static void rel_key(uint32_t a, uint32_t b, uint8_t key[8]) {
    memcpy(key, &a, 4);
    memcpy(key + 4, &b, 4);
}

static void load_rels(vg_engine_t *e) {
    uint8_t key[8];
    for (int i = 0; i < e->cfg->n_rels; i++) {
        uint8_t *v;
        /* provider -> customer edge, both directions recorded */
        rel_key(e->cfg->rel_provider[i], e->cfg->rel_customer[i], key);
        v = vg_hashmap_upsert(&e->rels, key, NULL);
        if (v) *v = REL_P2C;
        rel_key(e->cfg->rel_customer[i], e->cfg->rel_provider[i], key);
        v = vg_hashmap_upsert(&e->rels, key, NULL);
        if (v) *v = REL_C2P;
    }
    for (int i = 0; i < e->cfg->n_peer_rels; i++) {
        uint8_t *v;
        rel_key(e->cfg->peer_a[i], e->cfg->peer_b[i], key);
        v = vg_hashmap_upsert(&e->rels, key, NULL);
        if (v) *v = REL_PEER;
        rel_key(e->cfg->peer_b[i], e->cfg->peer_a[i], key);
        v = vg_hashmap_upsert(&e->rels, key, NULL);
        if (v) *v = REL_PEER;
    }
}

static int rel_of(vg_engine_t *e, uint32_t a, uint32_t b) {
    uint8_t key[8];
    rel_key(a, b, key);
    uint8_t *v = vg_hashmap_get(&e->rels, key);
    return v ? *v : REL_NONE;
}

/* ---- alert emission with cooldown ---------------------------------- */

static void emit_alert(vg_engine_t *e, vg_alert_t *a, const vg_event_t *ev) {
    /* cooldown key: type + prefix + observed asn */
    uint8_t key[24];
    key[0] = (uint8_t)a->type;
    key[1] = 0;
    prefix_key(&a->prefix, key + 2);
    memcpy(key + 20, &a->observed_asn, 4);

    double *last = vg_hashmap_upsert(&e->cooldown, key, NULL);
    if (last) {
        if (*last != 0 && ev->timestamp - *last < ALERT_COOLDOWN) {
            e->st.suppressed++;
            return;
        }
        *last = ev->timestamp;
    }

    a->timestamp = ev->timestamp;
    memcpy(a->peer, ev->peer, VG_PEER_STRLEN);
    e->st.alerts[a->type]++;
    if (e->sink) e->sink(a, e->user);
}

/* shared by detectors: format path/prefix into the evidence JSON */
static void evidence(vg_alert_t *a, const vg_event_t *ev, const char *extra) {
    char pfx[VG_PREFIX_STRLEN] = "", path[512] = "";
    vg_prefix_format(&ev->prefix, pfx, sizeof(pfx));
    vg_aspath_format(&ev->path, path, sizeof(path));
    snprintf(a->evidence, sizeof(a->evidence),
             "{\"prefix\":\"%s\",\"as_path\":\"%s\",\"peer\":\"%s\","
             "\"peer_asn\":%u,\"source\":\"%s\"%s%s}",
             pfx, path, ev->peer, ev->peer_asn, ev->source,
             extra && extra[0] ? "," : "", extra ? extra : "");
}

/* ---- baseline ------------------------------------------------------ */

static vg_baseline_entry_t *baseline_get(vg_engine_t *e, const vg_prefix_t *p) {
    uint8_t key[18];
    prefix_key(p, key);
    return vg_hashmap_get(&e->baseline, key);
}

static bool baseline_has_origin(const vg_baseline_entry_t *b, uint32_t asn) {
    for (int i = 0; i < b->n_origins; i++)
        if (b->origins[i] == asn) return true;
    return false;
}

/* Learn origins while the observation window is open; lock afterward. */
static void baseline_observe(vg_engine_t *e, const vg_event_t *ev) {
    if (ev->kind != VG_EV_ANNOUNCE) return;
    uint32_t origin = vg_event_origin(ev);
    if (origin == 0) return;

    uint8_t key[18];
    prefix_key(&ev->prefix, key);
    bool created;
    vg_baseline_entry_t *b = vg_hashmap_upsert(&e->baseline, key, &created);
    if (!b) return;
    if (created) {
        b->first_seen = ev->timestamp;
    }
    if (b->locked) return;
    if (ev->timestamp - b->first_seen > e->cfg->baseline_window) {
        b->locked = true;
        return;
    }
    if (!baseline_has_origin(b, origin) && b->n_origins < VG_BASELINE_MAX_ORIGINS)
        b->origins[b->n_origins++] = origin;
}

const vg_baseline_entry_t *vg_engine_baseline(vg_engine_t *e,
                                              const vg_prefix_t *p) {
    return baseline_get(e, p);
}

/* detectors (hijack.c, subprefix.c, leak.c, spike.c, rpki.c) */
void vg_detect_hijack(vg_engine_t *e, const vg_event_t *ev);
void vg_detect_subprefix(vg_engine_t *e, const vg_event_t *ev);
void vg_detect_leak(vg_engine_t *e, const vg_event_t *ev);
void vg_detect_spike(vg_engine_t *e, const vg_event_t *ev);
void vg_detect_rpki(vg_engine_t *e, const vg_event_t *ev);

/* internal accessors shared with detector files */
vg_baseline_entry_t *vg_engine_baseline_mut(vg_engine_t *e, const vg_prefix_t *p) {
    return baseline_get(e, p);
}
bool vg_baseline_has_origin(const vg_baseline_entry_t *b, uint32_t asn) {
    return baseline_has_origin(b, asn);
}
void vg_engine_emit(vg_engine_t *e, vg_alert_t *a, const vg_event_t *ev) {
    emit_alert(e, a, ev);
}
void vg_engine_evidence(vg_alert_t *a, const vg_event_t *ev, const char *extra) {
    evidence(a, ev, extra);
}
int vg_engine_rel(vg_engine_t *e, uint32_t a, uint32_t b) {
    return rel_of(e, a, b);
}
vg_rib_t *vg_engine_rib(vg_engine_t *e) { return e->rib; }
const vg_config_t *vg_engine_cfg(vg_engine_t *e) { return e->cfg; }
vg_rpki_t *vg_engine_rpki(vg_engine_t *e) { return e->rpki; }
vg_hashmap_t *vg_engine_spike_map(vg_engine_t *e, bool per_peer) {
    return per_peer ? &e->spike_peer : &e->spike_prefix;
}

/* ---- engine core ---------------------------------------------------- */

vg_engine_t *vg_engine_new(const vg_config_t *cfg, vg_rib_t *rib,
                           vg_alert_sink_fn sink, void *user) {
    vg_engine_t *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->cfg = cfg;
    e->rib = rib;
    e->sink = sink;
    e->user = user;
    if (vg_hashmap_init(&e->baseline, 18, sizeof(vg_baseline_entry_t)) != 0 ||
        vg_hashmap_init(&e->spike_prefix, 18, sizeof(vg_spike_state_t)) != 0 ||
        vg_hashmap_init(&e->spike_peer, VG_PEER_STRLEN, sizeof(vg_spike_state_t)) != 0 ||
        vg_hashmap_init(&e->cooldown, 24, sizeof(double)) != 0 ||
        vg_hashmap_init(&e->rels, 8, 1) != 0) {
        vg_engine_free(e);
        return NULL;
    }

    /* Seed the baseline from the config watchlist: entries with an
     * explicit origin are authoritative immediately. */
    for (int i = 0; i < cfg->n_watch; i++) {
        uint8_t key[18];
        prefix_key(&cfg->watch_prefix[i], key);
        vg_baseline_entry_t *b = vg_hashmap_upsert(&e->baseline, key, NULL);
        if (!b) continue;
        b->watched = true;
        if (cfg->watch_origin[i] != 0) {
            b->origins[0] = cfg->watch_origin[i];
            b->n_origins = 1;
            b->locked = true;
        }
    }
    load_rels(e);
    return e;
}

void vg_engine_free(vg_engine_t *e) {
    if (!e) return;
    vg_hashmap_free(&e->baseline);
    vg_hashmap_free(&e->spike_prefix);
    vg_hashmap_free(&e->spike_peer);
    vg_hashmap_free(&e->cooldown);
    vg_hashmap_free(&e->rels);
    free(e);
}

void vg_engine_set_rpki(vg_engine_t *e, vg_rpki_t *rpki) { e->rpki = rpki; }

void vg_engine_event(vg_engine_t *e, const vg_event_t *ev) {
    e->st.events++;
    vg_rib_apply(e->rib, ev);

    if (ev->kind == VG_EV_ANNOUNCE) {
        vg_detect_hijack(e, ev);
        vg_detect_subprefix(e, ev);
        vg_detect_leak(e, ev);
        vg_detect_rpki(e, ev);
    }
    vg_detect_spike(e, ev); /* announces and withdraws both count */

    baseline_observe(e, ev);
}

void vg_engine_sink(const vg_event_t *ev, void *user) {
    vg_engine_event((vg_engine_t *)user, ev);
}

void vg_engine_stats(vg_engine_t *e, vg_engine_stats_t *out) { *out = e->st; }
