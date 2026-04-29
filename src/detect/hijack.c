/*
 * Origin hijack: an announce whose origin AS is not in the prefix's
 * expected-origin set. "Expected" means the config watchlist origin
 * or the origins learned during the baseline observation window; the
 * baseline must be locked (window elapsed) before alerts fire, which
 * is what keeps normal multi-origin (MOAS) churn from false-alarming.
 */
#include "internal.h"

#include <stdio.h>
#include <string.h>

void vg_detect_hijack(vg_engine_t *e, const vg_event_t *ev) {
    uint32_t origin = vg_event_origin(ev);
    if (origin == 0) return;

    const vg_baseline_entry_t *b = vg_engine_baseline_mut(e, &ev->prefix);
    if (!b || !b->locked || b->n_origins == 0) return;
    if (vg_baseline_has_origin(b, origin)) return;
    /* Aggregation can legitimately surface odd origins in an AS_SET;
     * flag it, but don't call it a hijack. */
    if (ev->path.origin_from_set) return;

    vg_alert_t a;
    memset(&a, 0, sizeof(a));
    a.type = VG_ALERT_HIJACK;
    a.severity = b->watched ? VG_SEV_CRITICAL : VG_SEV_WARNING;
    a.prefix = ev->prefix;
    a.expected_asn = b->origins[0];
    a.observed_asn = origin;

    char pfx[VG_PREFIX_STRLEN];
    vg_prefix_format(&ev->prefix, pfx, sizeof(pfx));
    snprintf(a.summary, sizeof(a.summary),
             "possible hijack of %s: origin AS%u (expected AS%u)", pfx,
             origin, b->origins[0]);
    char extra[128];
    snprintf(extra, sizeof(extra), "\"expected_origin\":%u,\"observed_origin\":%u",
             b->origins[0], origin);
    vg_engine_evidence(&a, ev, extra);
    vg_engine_emit(e, &a, ev);
}
