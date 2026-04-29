/*
 * RPKI Route Origin Validation (RFC 6811) against a loaded set of
 * Validated ROA Payloads (VRPs), e.g. Routinator's JSON export.
 */
#ifndef VIGIL_RPKI_H
#define VIGIL_RPKI_H

#include "../vigil.h"

typedef enum {
    VG_ROV_NOTFOUND = 0, /* no covering VRP */
    VG_ROV_VALID    = 1,
    VG_ROV_INVALID  = 2,
} vg_rov_state_t;

typedef struct vg_rpki vg_rpki_t;

/* Load a VRP JSON file: {"roas":[{"asn":"AS13335","prefix":"1.1.1.0/24",
 * "maxLength":24,...},...]} (Routinator/rpki-client compatible).
 * Returns NULL on I/O or parse failure. */
vg_rpki_t *vg_rpki_load(const char *path);
void       vg_rpki_free(vg_rpki_t *r);
size_t     vg_rpki_count(const vg_rpki_t *r);

/* RFC 6811: VALID if some covering VRP authorizes (origin, len<=max),
 * INVALID if covering VRPs exist but none match, NOTFOUND otherwise. */
vg_rov_state_t vg_rpki_validate(const vg_rpki_t *r, const vg_prefix_t *p,
                                uint32_t origin_asn);

const char *vg_rov_str(vg_rov_state_t s);

#endif
