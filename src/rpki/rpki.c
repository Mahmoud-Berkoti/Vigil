/* Placeholder until Phase 6: no VRP set can be loaded, so validation
 * always reports NOTFOUND and the rpki detector stays silent. */
#include "rpki.h"

#include <stddef.h>

vg_rpki_t *vg_rpki_load(const char *path) {
    (void)path;
    return NULL;
}

void vg_rpki_free(vg_rpki_t *r) { (void)r; }

size_t vg_rpki_count(const vg_rpki_t *r) {
    (void)r;
    return 0;
}

vg_rov_state_t vg_rpki_validate(const vg_rpki_t *r, const vg_prefix_t *p,
                                uint32_t origin_asn) {
    (void)r;
    (void)p;
    (void)origin_asn;
    return VG_ROV_NOTFOUND;
}

const char *vg_rov_str(vg_rov_state_t s) {
    switch (s) {
    case VG_ROV_VALID:    return "valid";
    case VG_ROV_INVALID:  return "invalid";
    case VG_ROV_NOTFOUND: return "notfound";
    }
    return "unknown";
}
