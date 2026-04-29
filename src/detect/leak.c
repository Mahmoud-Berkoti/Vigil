/*
 * Route leak: valley-free violation (Gao-Rexford model). Traversing an
 * AS path from the origin toward the collector peer, a route may go
 * "up" customer->provider links, cross at most one peer link, then go
 * "down" provider->customer links. Once it has gone down or crossed a
 * peer link, any subsequent "up" or peer hop means some AS re-exported
 * a route it should only use for itself — a leak.
 *
 * HEURISTIC AND APPROXIMATE, by design: only edges present in the
 * configured relationship set (rel_provider / rel_peer) are judged;
 * unknown edges are skipped so the detector cannot false-positive on
 * ASes we know nothing about. The flagged AS is the one that
 * propagated after the path had already gone down/sideways.
 */
#include "internal.h"

#include <stdio.h>
#include <string.h>

void vg_detect_leak(vg_engine_t *e, const vg_event_t *ev) {
    const vg_aspath_t *p = &ev->path;
    if (p->count < 3) return;

    /* Walk origin -> collector, i.e. from the END of the path.
     * hop as[i+1] received the route from as[i]... in AS_PATH order the
     * leftmost AS is nearest the collector; propagation order is
     * right-to-left. Edge (as[i+1] -> as[i]) = "as[i] learned from
     * as[i+1]"; the relationship as[i+1]->as[i] classifies the export. */
    bool descended = false; /* went provider->customer or crossed a peer */
    for (int i = (int)p->count - 2; i >= 0; i--) {
        uint32_t from = p->as[i + 1]; /* exporter */
        uint32_t to = p->as[i];       /* receiver */
        if (from == to) continue;     /* prepending */

        int rel = vg_engine_rel(e, from, to);
        if (rel == VG_REL_NONE) continue;

        /* Export direction semantics:
         *   from->to is C2P: "from" (customer) exported to its provider.
         *   from->to is PEER: exported across a peering.
         * Both are only legitimate for routes still on the way "up". */
        bool upward = (rel == VG_REL_C2P) || (rel == VG_REL_PEER);
        if (descended && upward) {
            vg_alert_t a;
            memset(&a, 0, sizeof(a));
            a.type = VG_ALERT_LEAK;
            a.severity = VG_SEV_WARNING;
            a.prefix = ev->prefix;
            a.observed_asn = from; /* the leaker */
            a.expected_asn = to;   /* who it leaked to */

            char pfx[VG_PREFIX_STRLEN], path[512];
            vg_prefix_format(&ev->prefix, pfx, sizeof(pfx));
            vg_aspath_format(p, path, sizeof(path));
            snprintf(a.summary, sizeof(a.summary),
                     "route leak: AS%u re-exported %s %s AS%u after a "
                     "downward/peer segment (path %s)",
                     from, pfx, rel == VG_REL_PEER ? "across peering to" : "up to",
                     to, path);
            char extra[96];
            snprintf(extra, sizeof(extra), "\"leaker_asn\":%u,\"leaked_to\":%u",
                     from, to);
            vg_engine_evidence(&a, ev, extra);
            vg_engine_emit(e, &a, ev);
            return;
        }
        if (rel == VG_REL_P2C || rel == VG_REL_PEER) descended = true;
    }
}
