/* Shared between the engine core and the detector files. */
#ifndef VIGIL_DETECT_INTERNAL_H
#define VIGIL_DETECT_INTERNAL_H

#include "../util/hashmap.h"
#include "detect.h"

vg_baseline_entry_t *vg_engine_baseline_mut(vg_engine_t *e, const vg_prefix_t *p);
bool vg_baseline_has_origin(const vg_baseline_entry_t *b, uint32_t asn);
void vg_engine_emit(vg_engine_t *e, vg_alert_t *a, const vg_event_t *ev);
void vg_engine_evidence(vg_alert_t *a, const vg_event_t *ev, const char *extra);

enum { VG_REL_NONE = 0, VG_REL_P2C = 1, VG_REL_C2P = 2, VG_REL_PEER = 3 };

/* rolling two-bucket window state for spike detection */
typedef struct {
    double   window_start;
    uint32_t cur, prev;
    uint64_t total;
    double   first_ts;
} vg_spike_state_t;
int vg_engine_rel(vg_engine_t *e, uint32_t a, uint32_t b);

vg_rib_t          *vg_engine_rib(vg_engine_t *e);
const vg_config_t *vg_engine_cfg(vg_engine_t *e);
vg_rpki_t         *vg_engine_rpki(vg_engine_t *e);
vg_hashmap_t      *vg_engine_spike_map(vg_engine_t *e, bool per_peer);

void vg_detect_hijack(vg_engine_t *e, const vg_event_t *ev);
void vg_detect_subprefix(vg_engine_t *e, const vg_event_t *ev);
void vg_detect_leak(vg_engine_t *e, const vg_event_t *ev);
void vg_detect_spike(vg_engine_t *e, const vg_event_t *ev);
void vg_detect_rpki(vg_engine_t *e, const vg_event_t *ev);

#endif
