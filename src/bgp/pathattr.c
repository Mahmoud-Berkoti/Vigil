#include "bgp.h"

#include <string.h>

enum { AS_SET = 1, AS_SEQUENCE = 2 };

static uint32_t rd32(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | b[3];
}
static uint16_t rd16(const uint8_t *b) {
    return (uint16_t)((b[0] << 8) | b[1]);
}

int vg_aspath_decode(const uint8_t *buf, size_t n, int asn_size,
                     vg_aspath_t *out) {
    memset(out, 0, sizeof(*out));
    size_t off = 0;
    while (off < n) {
        if (n - off < 2) return VG_BGP_ETRUNC;
        uint8_t seg_type = buf[off];
        uint8_t seg_count = buf[off + 1];
        off += 2;
        if (seg_type != AS_SET && seg_type != AS_SEQUENCE)
            return VG_BGP_ESEGTYPE;
        size_t need = (size_t)seg_count * (size_t)asn_size;
        if (n - off < need) return VG_BGP_ETRUNC;

        for (int i = 0; i < seg_count; i++) {
            uint32_t asn = asn_size == 4 ? rd32(buf + off) : rd16(buf + off);
            off += (size_t)asn_size;
            if (out->count >= VG_ASPATH_MAX) return VG_BGP_E2BIG;
            out->as[out->count++] = asn;
        }
        /* If the path ends in an AS_SET, "the origin" is a set of
         * aggregated ASes rather than a single AS. */
        out->origin_from_set = (seg_type == AS_SET);
    }
    return VG_BGP_OK;
}
