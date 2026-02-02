#include "bgp.h"

#include <string.h>

const char *vg_bgp_strerror(int err) {
    switch (err) {
    case VG_BGP_OK:         return "ok";
    case VG_BGP_EBADMARKER: return "bad marker";
    case VG_BGP_EBADLEN:    return "bad length";
    case VG_BGP_EBADTYPE:   return "bad message type";
    case VG_BGP_ETRUNC:     return "truncated";
    case VG_BGP_EATTRLEN:   return "inconsistent attribute length";
    case VG_BGP_EPREFIXLEN: return "prefix length out of range";
    case VG_BGP_ESEGTYPE:   return "invalid AS_PATH segment type";
    case VG_BGP_EAFI:       return "unsupported AFI/SAFI";
    case VG_BGP_E2BIG:      return "too many elements";
    case VG_BGP_EMISSING:   return "missing mandatory attribute";
    }
    return "unknown error";
}

int vg_bgp_parse_header(const uint8_t *buf, size_t n, vg_bgp_hdr_t *out) {
    if (n < VG_BGP_HEADER_LEN) return VG_BGP_ETRUNC;
    for (int i = 0; i < 16; i++)
        if (buf[i] != 0xFF) return VG_BGP_EBADMARKER;

    uint16_t len = (uint16_t)((buf[16] << 8) | buf[17]);
    uint8_t type = buf[18];

    if (len < VG_BGP_HEADER_LEN || len > VG_BGP_MAX_LEN || len > n)
        return VG_BGP_EBADLEN;

    uint16_t min_len;
    switch (type) {
    case VG_BGP_OPEN:         min_len = 29; break; /* hdr + 10 */
    case VG_BGP_UPDATE:       min_len = 23; break; /* hdr + 2 + 2 */
    case VG_BGP_NOTIFICATION: min_len = 21; break; /* hdr + 2 */
    case VG_BGP_KEEPALIVE:    min_len = 19; break; /* header only */
    default:                  return VG_BGP_EBADTYPE;
    }
    if (len < min_len) return VG_BGP_EBADLEN;
    if (type == VG_BGP_KEEPALIVE && len != 19) return VG_BGP_EBADLEN;

    out->len = len;
    out->type = type;
    return VG_BGP_OK;
}
