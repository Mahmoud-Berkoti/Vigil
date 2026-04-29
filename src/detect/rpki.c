/*
 * RPKI-invalid announcements: RFC 6811 origin validation against the
 * loaded VRP set. Disabled (no-op) until an RPKI table is attached.
 */
#include "../rpki/rpki.h"
#include "internal.h"

#include <stdio.h>
#include <string.h>

void vg_detect_rpki(vg_engine_t *e, const vg_event_t *ev) {
    vg_rpki_t *rpki = vg_engine_rpki(e);
    if (!rpki) return;
    uint32_t origin = vg_event_origin(ev);
    if (origin == 0) return;

    if (vg_rpki_validate(rpki, &ev->prefix, origin) != VG_ROV_INVALID)
        return;

    vg_alert_t a;
    memset(&a, 0, sizeof(a));
    a.type = VG_ALERT_RPKI_INVALID;
    a.severity = VG_SEV_WARNING;
    a.prefix = ev->prefix;
    a.observed_asn = origin;

    char pfx[VG_PREFIX_STRLEN];
    vg_prefix_format(&ev->prefix, pfx, sizeof(pfx));
    snprintf(a.summary, sizeof(a.summary),
             "RPKI-invalid announcement: %s from origin AS%u", pfx, origin);
    vg_engine_evidence(&a, ev, "\"rov\":\"invalid\"");
    vg_engine_emit(e, &a, ev);
}
