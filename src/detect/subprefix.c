/*
 * Sub-prefix hijack: a more-specific of a known prefix appears with an
 * origin outside the covering prefix's expected set. This is the
 * classic dangerous case — more-specifics win in forwarding, so the
 * attacker attracts the traffic even though the victim's announcement
 * is still up.
 *
 * We check the announced prefix against every covering (less-specific)
 * prefix that has a locked baseline. The announced prefix having its
 * own locked baseline containing this origin means it's a long-known
 * more-specific, not a new carve-out — no alert.
 */
#include "internal.h"

#include <stdio.h>
#include <string.h>

void vg_detect_subprefix(vg_engine_t *e, const vg_event_t *ev) {
    uint32_t origin = vg_event_origin(ev);
    if (origin == 0 || ev->path.origin_from_set) return;

    /* known-good more-specific? */
    const vg_baseline_entry_t *own = vg_engine_baseline_mut(e, &ev->prefix);
    if (own && vg_baseline_has_origin(own, origin)) return;

    /* walk covering prefixes from shortest mask down: check each with
     * a locked baseline; alert on the most specific mismatch */
    vg_prefix_t probe = ev->prefix;
    for (int len = ev->prefix.len - 1; len >= 0; len--) {
        probe.len = (uint8_t)len;
        vg_prefix_t cover = probe;
        vg_prefix_normalize(&cover);
        const vg_baseline_entry_t *b = vg_engine_baseline_mut(e, &cover);
        if (!b || !b->locked || b->n_origins == 0) continue;

        if (vg_baseline_has_origin(b, origin)) return; /* same owner */

        vg_alert_t a;
        memset(&a, 0, sizeof(a));
        a.type = VG_ALERT_SUBPREFIX;
        a.severity = b->watched ? VG_SEV_CRITICAL : VG_SEV_WARNING;
        a.prefix = ev->prefix;
        a.expected_asn = b->origins[0];
        a.observed_asn = origin;

        char pfx[VG_PREFIX_STRLEN], cpfx[VG_PREFIX_STRLEN];
        vg_prefix_format(&ev->prefix, pfx, sizeof(pfx));
        vg_prefix_format(&cover, cpfx, sizeof(cpfx));
        snprintf(a.summary, sizeof(a.summary),
                 "sub-prefix hijack: %s (origin AS%u) carves %s owned by AS%u",
                 pfx, origin, cpfx, b->origins[0]);
        char extra[160];
        snprintf(extra, sizeof(extra),
                 "\"covering_prefix\":\"%s\",\"covering_origin\":%u,"
                 "\"observed_origin\":%u", cpfx, b->origins[0], origin);
        vg_engine_evidence(&a, ev, extra);
        vg_engine_emit(e, &a, ev);
        return; /* one alert per announce is enough */
    }
}
