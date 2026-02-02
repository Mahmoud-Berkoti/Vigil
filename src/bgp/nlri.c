#include "bgp.h"

#include <string.h>

int vg_nlri_decode(const uint8_t *buf, size_t n, vg_family_t family,
                   vg_prefix_t *out) {
    if (n < 1) return VG_BGP_ETRUNC;
    uint8_t plen = buf[0];
    uint8_t max = family == VG_AF_INET ? 32 : 128;
    if (plen > max) return VG_BGP_EPREFIXLEN;

    size_t nbytes = ((size_t)plen + 7) / 8;
    if (n < 1 + nbytes) return VG_BGP_ETRUNC;

    memset(out, 0, sizeof(*out));
    out->family = (uint8_t)family;
    out->len = plen;
    memcpy(out->addr, buf + 1, nbytes);
    /* RFC 4271: trailing bits in the last byte are irrelevant on the
     * wire; normalize so prefixes compare equal. */
    vg_prefix_normalize(out);
    return (int)(1 + nbytes);
}

int vg_nlri_encode(const vg_prefix_t *p, uint8_t *buf, size_t n) {
    size_t nbytes = ((size_t)p->len + 7) / 8;
    if (n < 1 + nbytes) return VG_BGP_ETRUNC;
    buf[0] = p->len;
    memcpy(buf + 1, p->addr, nbytes);
    return (int)(1 + nbytes);
}
