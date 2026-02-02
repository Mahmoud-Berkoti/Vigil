#include "bgp.h"

#include <string.h>

static uint32_t rd32(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | b[3];
}
static uint16_t rd16(const uint8_t *b) {
    return (uint16_t)((b[0] << 8) | b[1]);
}

/* Parse capabilities inside one Optional Parameter of type 2 */
static int parse_caps(const uint8_t *p, size_t n, vg_bgp_open_t *out) {
    size_t off = 0;
    while (off < n) {
        if (n - off < 2) return VG_BGP_ETRUNC;
        uint8_t code = p[off], clen = p[off + 1];
        off += 2;
        if (n - off < clen) return VG_BGP_ETRUNC;
        const uint8_t *v = p + off;

        if (code == 65) { /* 4-octet ASN, RFC 6793 */
            if (clen != 4) return VG_BGP_EATTRLEN;
            out->cap_as4 = true;
            out->as4 = rd32(v);
        } else if (code == 1) { /* multiprotocol, RFC 4760 */
            if (clen != 4) return VG_BGP_EATTRLEN;
            uint16_t afi = rd16(v);
            uint8_t safi = v[3];
            if (safi == 1) {
                if (afi == 1) out->cap_mp_ipv4 = true;
                if (afi == 2) out->cap_mp_ipv6 = true;
            }
        }
        off += clen;
    }
    return VG_BGP_OK;
}

int vg_bgp_parse_open(const uint8_t *payload, size_t n, vg_bgp_open_t *out) {
    memset(out, 0, sizeof(*out));
    if (n < 10) return VG_BGP_ETRUNC;

    out->version = payload[0];
    out->my_as = rd16(payload + 1);
    out->hold_time = rd16(payload + 3);
    out->bgp_id = rd32(payload + 5);
    uint8_t opt_len = payload[9];
    if ((size_t)opt_len + 10 > n) return VG_BGP_EBADLEN;

    size_t off = 10;
    size_t end = 10u + opt_len;
    while (off < end) {
        if (end - off < 2) return VG_BGP_ETRUNC;
        uint8_t ptype = payload[off], plen = payload[off + 1];
        off += 2;
        if (end - off < plen) return VG_BGP_ETRUNC;
        if (ptype == 2) { /* capabilities */
            int rc = parse_caps(payload + off, plen, out);
            if (rc != VG_BGP_OK) return rc;
        }
        off += plen;
    }
    return VG_BGP_OK;
}
