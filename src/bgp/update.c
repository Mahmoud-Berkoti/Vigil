#include "bgp.h"

#include <string.h>

static uint32_t rd32(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | b[3];
}
static uint16_t rd16(const uint8_t *b) {
    return (uint16_t)((b[0] << 8) | b[1]);
}

/* Decode a run of NLRI prefixes filling arr (cap entries). */
static int decode_nlri_run(const uint8_t *buf, size_t n, vg_family_t fam,
                           vg_prefix_t *arr, uint16_t *count, size_t cap) {
    size_t off = 0;
    *count = 0;
    while (off < n) {
        if (*count >= cap) return VG_BGP_E2BIG;
        int used = vg_nlri_decode(buf + off, n - off, fam, &arr[*count]);
        if (used < 0) return used;
        (*count)++;
        off += (size_t)used;
    }
    return VG_BGP_OK;
}

/* RFC 6793 §4.2.3: reconstruct the real path when a 2-octet speaker
 * relayed a 4-octet path via AS4_PATH. */
static void merge_as4_path(vg_aspath_t *path, const vg_aspath_t *as4path) {
    if (as4path->count == 0 || as4path->count > path->count) return;
    uint16_t keep = (uint16_t)(path->count - as4path->count);
    for (uint16_t i = 0; i < as4path->count; i++)
        path->as[keep + i] = as4path->as[i];
    path->origin_from_set = as4path->origin_from_set;
}

static int parse_mp_reach(const uint8_t *v, size_t alen, vg_bgp_update_t *u) {
    if (alen < 5) return VG_BGP_ETRUNC;
    uint16_t afi = rd16(v);
    uint8_t safi = v[2];
    uint8_t nhlen = v[3];
    if ((afi != 1 && afi != 2) || safi != 1) return VG_BGP_EAFI;
    if (alen < 4u + nhlen + 1u) return VG_BGP_ETRUNC;
    /* v6 next hop may be 16 (global) or 32 (global + link-local) */
    if (nhlen > 32) return VG_BGP_EATTRLEN;

    u->has_mp_reach = true;
    u->mp_af = afi == 1 ? VG_AF_INET : VG_AF_INET6;
    u->mp_next_hop_len = nhlen > 16 ? 16 : nhlen;
    memcpy(u->mp_next_hop, v + 4, u->mp_next_hop_len);

    size_t off = 4u + nhlen + 1u; /* +1 reserved byte */
    return decode_nlri_run(v + off, alen - off, (vg_family_t)u->mp_af,
                           u->mp_nlri, &u->n_mp_nlri, VG_BGP_MAX_ROUTES);
}

static int parse_mp_unreach(const uint8_t *v, size_t alen, vg_bgp_update_t *u) {
    if (alen < 3) return VG_BGP_ETRUNC;
    uint16_t afi = rd16(v);
    uint8_t safi = v[2];
    if ((afi != 1 && afi != 2) || safi != 1) return VG_BGP_EAFI;
    u->has_mp_unreach = true;
    u->mp_unreach_af = afi == 1 ? VG_AF_INET : VG_AF_INET6;
    return decode_nlri_run(v + 3, alen - 3, (vg_family_t)u->mp_unreach_af,
                           u->mp_unreach, &u->n_mp_unreach, VG_BGP_MAX_ROUTES);
}

int vg_bgp_parse_attrs(const uint8_t *attrs, size_t attrs_end, bool as4,
                       bool td2_mp_reach, vg_bgp_update_t *out) {
    int rc;
    vg_aspath_t as4_path;
    memset(&as4_path, 0, sizeof(as4_path));
    bool have_as4_path = false;

    size_t a = 0;
    while (a < attrs_end) {
        if (attrs_end - a < 2) return VG_BGP_ETRUNC;
        uint8_t flags = attrs[a];
        uint8_t type = attrs[a + 1];
        a += 2;

        size_t alen;
        if (flags & VG_ATTRF_EXTLEN) {
            if (attrs_end - a < 2) return VG_BGP_ETRUNC;
            alen = rd16(attrs + a);
            a += 2;
        } else {
            if (attrs_end - a < 1) return VG_BGP_ETRUNC;
            alen = attrs[a];
            a += 1;
        }
        if (alen > attrs_end - a) return VG_BGP_EATTRLEN;
        const uint8_t *v = attrs + a;

        switch (type) {
        case VG_ATTR_ORIGIN:
            if (alen != 1) return VG_BGP_EATTRLEN;
            if (v[0] > 2) return VG_BGP_EATTRLEN;
            out->origin = v[0];
            break;
        case VG_ATTR_AS_PATH:
            rc = vg_aspath_decode(v, alen, as4 ? 4 : 2, &out->path);
            if (rc != VG_BGP_OK) return rc;
            out->has_path = true;
            break;
        case VG_ATTR_AS4_PATH:
            rc = vg_aspath_decode(v, alen, 4, &as4_path);
            if (rc != VG_BGP_OK) return rc;
            have_as4_path = true;
            break;
        case VG_ATTR_NEXT_HOP:
            if (alen != 4) return VG_BGP_EATTRLEN;
            memcpy(out->next_hop, v, 4);
            out->has_next_hop = true;
            break;
        case VG_ATTR_MED:
            if (alen != 4) return VG_BGP_EATTRLEN;
            out->med = rd32(v);
            out->has_med = true;
            break;
        case VG_ATTR_LOCAL_PREF:
            if (alen != 4) return VG_BGP_EATTRLEN;
            out->local_pref = rd32(v);
            out->has_local_pref = true;
            break;
        case VG_ATTR_ATOMIC_AGGREGATE:
            if (alen != 0) return VG_BGP_EATTRLEN;
            break;
        case VG_ATTR_AGGREGATOR:
            if (alen != (size_t)(as4 ? 8 : 6)) return VG_BGP_EATTRLEN;
            break;
        case VG_ATTR_AS4_AGGREGATOR:
            if (alen != 8) return VG_BGP_EATTRLEN;
            break;
        case VG_ATTR_COMMUNITIES:
            if (alen % 4 != 0) return VG_BGP_EATTRLEN;
            for (size_t i = 0; i + 4 <= alen && out->n_communities < VG_MAX_COMMUNITIES; i += 4)
                out->communities[out->n_communities++] = rd32(v + i);
            break;
        case VG_ATTR_MP_REACH_NLRI:
            /* RFC 6396 §4.3.4: inside TABLE_DUMP_V2 the attribute is
             * abridged to nexthop-length + nexthop only. */
            if (td2_mp_reach) {
                if (alen < 1 || (size_t)v[0] + 1 > alen || v[0] > 32)
                    return VG_BGP_EATTRLEN;
                out->has_mp_reach = true;
                out->mp_next_hop_len = v[0] > 16 ? 16 : v[0];
                memcpy(out->mp_next_hop, v + 1, out->mp_next_hop_len);
            } else {
                rc = parse_mp_reach(v, alen, out);
                if (rc != VG_BGP_OK) return rc;
            }
            break;
        case VG_ATTR_MP_UNREACH_NLRI:
            rc = parse_mp_unreach(v, alen, out);
            if (rc != VG_BGP_OK) return rc;
            break;
        default:
            /* Unknown well-known (non-optional) attributes are a
             * protocol error; unknown optional attributes are normal
             * (we're a passive monitor: count and move on). */
            if (!(flags & VG_ATTRF_OPTIONAL)) return VG_BGP_EATTRLEN;
            out->n_unknown_attrs++;
            break;
        }
        a += alen;
    }

    if (have_as4_path && !as4 && out->has_path)
        merge_as4_path(&out->path, &as4_path);

    return VG_BGP_OK;
}

int vg_bgp_parse_update(const uint8_t *payload, size_t n, bool as4,
                        vg_bgp_update_t *out) {
    memset(out, 0, sizeof(*out));
    out->origin = VG_ORIGIN_UNSET;

    /* Withdrawn Routes: 2-byte length + v4 NLRI run */
    if (n < 2) return VG_BGP_ETRUNC;
    uint16_t wlen = rd16(payload);
    if ((size_t)wlen + 2 > n) return VG_BGP_EBADLEN;
    int rc = decode_nlri_run(payload + 2, wlen, VG_AF_INET, out->withdrawn,
                             &out->n_withdrawn, VG_BGP_MAX_ROUTES);
    if (rc != VG_BGP_OK) return rc;
    size_t off = 2u + wlen;

    /* Total Path Attribute Length */
    if (n - off < 2) return VG_BGP_ETRUNC;
    uint16_t alen_total = rd16(payload + off);
    off += 2;
    if (alen_total > n - off) return VG_BGP_EBADLEN;
    size_t nlri_off = off + alen_total;

    rc = vg_bgp_parse_attrs(payload + off, alen_total, as4, false, out);
    if (rc != VG_BGP_OK) return rc;

    /* Classic v4 NLRI: rest of message */
    rc = decode_nlri_run(payload + nlri_off, n - nlri_off, VG_AF_INET,
                         out->nlri, &out->n_nlri, VG_BGP_MAX_ROUTES);
    if (rc != VG_BGP_OK) return rc;

    /* RFC 4271 §6.3: ORIGIN, AS_PATH, NEXT_HOP are mandatory when the
     * message announces classic NLRI. */
    if (out->n_nlri > 0 &&
        (!out->has_path || out->origin == VG_ORIGIN_UNSET || !out->has_next_hop))
        return VG_BGP_EMISSING;
    if (out->n_mp_nlri > 0 && (!out->has_path || out->origin == VG_ORIGIN_UNSET))
        return VG_BGP_EMISSING;

    return VG_BGP_OK;
}

/* ------------------------------------------------------------------ */
/* Serializer (tests + synthetic fixtures)                             */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t *buf;
    size_t cap, off;
    bool overflow;
} wr_t;

static void w8(wr_t *w, uint8_t v) {
    if (w->off + 1 > w->cap) { w->overflow = true; return; }
    w->buf[w->off++] = v;
}
static void w16(wr_t *w, uint16_t v) {
    w8(w, (uint8_t)(v >> 8));
    w8(w, (uint8_t)v);
}
static void w32(wr_t *w, uint32_t v) {
    w16(w, (uint16_t)(v >> 16));
    w16(w, (uint16_t)v);
}
static void wbytes(wr_t *w, const uint8_t *p, size_t n) {
    if (w->off + n > w->cap) { w->overflow = true; return; }
    memcpy(w->buf + w->off, p, n);
    w->off += n;
}

static void w_attr_hdr(wr_t *w, uint8_t flags, uint8_t type, size_t len) {
    if (len > 255) flags |= VG_ATTRF_EXTLEN;
    w8(w, flags);
    w8(w, type);
    if (flags & VG_ATTRF_EXTLEN) w16(w, (uint16_t)len);
    else w8(w, (uint8_t)len);
}

static size_t nlri_run_len(const vg_prefix_t *arr, uint16_t n) {
    size_t total = 0;
    for (uint16_t i = 0; i < n; i++) total += 1 + ((size_t)arr[i].len + 7) / 8;
    return total;
}

static void w_nlri_run(wr_t *w, const vg_prefix_t *arr, uint16_t n) {
    for (uint16_t i = 0; i < n; i++) {
        uint8_t tmp[17];
        int used = vg_nlri_encode(&arr[i], tmp, sizeof(tmp));
        if (used < 0) { w->overflow = true; return; }
        wbytes(w, tmp, (size_t)used);
    }
}

int vg_bgp_write_update(const vg_bgp_update_t *u, bool as4, uint8_t *buf,
                        size_t n) {
    wr_t w = {buf, n, 0, false};

    for (int i = 0; i < 16; i++) w8(&w, 0xFF);
    size_t len_pos = w.off;
    w16(&w, 0); /* patched at the end */
    w8(&w, VG_BGP_UPDATE);

    /* withdrawn */
    size_t wlen = nlri_run_len(u->withdrawn, u->n_withdrawn);
    w16(&w, (uint16_t)wlen);
    w_nlri_run(&w, u->withdrawn, u->n_withdrawn);

    /* attributes */
    size_t attr_len_pos = w.off;
    w16(&w, 0); /* patched */
    size_t attrs_start = w.off;

    if (u->origin != VG_ORIGIN_UNSET) {
        w_attr_hdr(&w, VG_ATTRF_TRANSITIVE, VG_ATTR_ORIGIN, 1);
        w8(&w, u->origin);
    }
    if (u->has_path) {
        size_t asz = as4 ? 4 : 2;
        /* single AS_SEQUENCE segment (max 255 per segment) */
        uint16_t remaining = u->path.count;
        size_t plen = 0;
        uint16_t idx = 0;
        (void)idx;
        size_t nsegs = u->path.count == 0 ? 0 : ((size_t)u->path.count + 254) / 255;
        plen = nsegs * 2 + (size_t)u->path.count * asz;
        w_attr_hdr(&w, VG_ATTRF_TRANSITIVE, VG_ATTR_AS_PATH, plen);
        uint16_t pos = 0;
        while (remaining > 0) {
            uint8_t seg = remaining > 255 ? 255 : (uint8_t)remaining;
            w8(&w, 2); /* AS_SEQUENCE */
            w8(&w, seg);
            for (uint8_t i = 0; i < seg; i++) {
                uint32_t asn = u->path.as[pos++];
                if (as4) w32(&w, asn);
                else w16(&w, (uint16_t)asn);
            }
            remaining = (uint16_t)(remaining - seg);
        }
    }
    if (u->has_next_hop) {
        w_attr_hdr(&w, VG_ATTRF_TRANSITIVE, VG_ATTR_NEXT_HOP, 4);
        wbytes(&w, u->next_hop, 4);
    }
    if (u->has_med) {
        w_attr_hdr(&w, VG_ATTRF_OPTIONAL, VG_ATTR_MED, 4);
        w32(&w, u->med);
    }
    if (u->has_local_pref) {
        w_attr_hdr(&w, VG_ATTRF_TRANSITIVE, VG_ATTR_LOCAL_PREF, 4);
        w32(&w, u->local_pref);
    }
    if (u->n_communities > 0) {
        w_attr_hdr(&w, VG_ATTRF_OPTIONAL | VG_ATTRF_TRANSITIVE,
                   VG_ATTR_COMMUNITIES, (size_t)u->n_communities * 4);
        for (uint16_t i = 0; i < u->n_communities; i++)
            w32(&w, u->communities[i]);
    }
    if (u->has_mp_reach) {
        size_t nlen = nlri_run_len(u->mp_nlri, u->n_mp_nlri);
        size_t alen = 2 + 1 + 1 + u->mp_next_hop_len + 1 + nlen;
        w_attr_hdr(&w, VG_ATTRF_OPTIONAL, VG_ATTR_MP_REACH_NLRI, alen);
        w16(&w, u->mp_af == VG_AF_INET ? 1 : 2);
        w8(&w, 1); /* SAFI unicast */
        w8(&w, u->mp_next_hop_len);
        wbytes(&w, u->mp_next_hop, u->mp_next_hop_len);
        w8(&w, 0); /* reserved */
        w_nlri_run(&w, u->mp_nlri, u->n_mp_nlri);
    }
    if (u->has_mp_unreach) {
        size_t nlen = nlri_run_len(u->mp_unreach, u->n_mp_unreach);
        w_attr_hdr(&w, VG_ATTRF_OPTIONAL, VG_ATTR_MP_UNREACH_NLRI, 3 + nlen);
        w16(&w, u->mp_unreach_af == VG_AF_INET ? 1 : 2);
        w8(&w, 1);
        w_nlri_run(&w, u->mp_unreach, u->n_mp_unreach);
    }

    size_t attrs_len = w.off - attrs_start;
    /* NLRI */
    w_nlri_run(&w, u->nlri, u->n_nlri);

    if (w.overflow || w.off > VG_BGP_MAX_LEN) return VG_BGP_E2BIG;

    buf[len_pos] = (uint8_t)(w.off >> 8);
    buf[len_pos + 1] = (uint8_t)w.off;
    buf[attr_len_pos] = (uint8_t)(attrs_len >> 8);
    buf[attr_len_pos + 1] = (uint8_t)attrs_len;
    return (int)w.off;
}
