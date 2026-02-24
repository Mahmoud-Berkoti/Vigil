#include "mrt.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

static uint32_t rd32(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | b[3];
}
static uint16_t rd16(const uint8_t *b) {
    return (uint16_t)((b[0] << 8) | b[1]);
}

int vg_mrt_open(vg_mrt_reader_t *r, const char *path) {
    memset(r, 0, sizeof(*r));
    r->f = fopen(path, "rb");
    if (!r->f) return -1;
    r->cap = 65536;
    r->buf = malloc(r->cap);
    if (!r->buf) {
        fclose(r->f);
        r->f = NULL;
        return -1;
    }
    return 0;
}

void vg_mrt_close(vg_mrt_reader_t *r) {
    if (r->f) fclose(r->f);
    free(r->buf);
    r->f = NULL;
    r->buf = NULL;
}

int vg_mrt_next(vg_mrt_reader_t *r, vg_mrt_rec_t *rec) {
    uint8_t hdr[12];
    size_t got = fread(hdr, 1, sizeof(hdr), r->f);
    if (got == 0 && feof(r->f)) return 0;
    if (got != sizeof(hdr)) return -1;

    rec->timestamp = (double)rd32(hdr);
    rec->type = rd16(hdr + 4);
    rec->subtype = rd16(hdr + 6);
    rec->length = rd32(hdr + 8);
    if (rec->length > VG_MRT_MAX_BODY) return -1;

    if (rec->length > r->cap) {
        size_t ncap = rec->length;
        uint8_t *nbuf = realloc(r->buf, ncap);
        if (!nbuf) return -1;
        r->buf = nbuf;
        r->cap = ncap;
    }
    if (fread(r->buf, 1, rec->length, r->f) != rec->length) return -1;
    rec->body = r->buf;

    /* Extended-timestamp variants carry microseconds first */
    if (rec->type == VG_MRT_BGP4MP_ET) {
        if (rec->length < 4) return -1;
        rec->timestamp += (double)rd32(rec->body) / 1e6;
        rec->body += 4;
        rec->length -= 4;
    }
    r->records_read++;
    return 1;
}

static void ip_to_text(uint8_t family, const uint8_t *addr, char *out, size_t n) {
    int af = family == VG_AF_INET ? AF_INET : AF_INET6;
    if (!inet_ntop(af, addr, out, (socklen_t)n)) snprintf(out, n, "?");
}

int vg_mrt_parse_bgp4mp(const vg_mrt_rec_t *rec, vg_mrt_bgp4mp_t *out) {
    memset(out, 0, sizeof(*out));
    if (rec->type != VG_MRT_BGP4MP && rec->type != VG_MRT_BGP4MP_ET)
        return VG_BGP_EBADTYPE;
    bool as4 = rec->subtype == VG_BGP4MP_MESSAGE_AS4 ||
               rec->subtype == VG_BGP4MP_MESSAGE_AS4_LOCAL;
    if (!as4 && rec->subtype != VG_BGP4MP_MESSAGE &&
        rec->subtype != VG_BGP4MP_MESSAGE_LOCAL)
        return VG_BGP_EBADTYPE; /* state changes handled by caller */

    const uint8_t *b = rec->body;
    size_t n = rec->length;
    size_t assz = as4 ? 4 : 2;
    if (n < assz * 2 + 4) return VG_BGP_ETRUNC;

    size_t off = 0;
    out->peer_as = as4 ? rd32(b) : rd16(b);
    off += assz;
    out->local_as = as4 ? rd32(b + off) : rd16(b + off);
    off += assz;
    off += 2; /* interface index */
    uint16_t afi = rd16(b + off);
    off += 2;
    size_t iplen;
    if (afi == 1) {
        out->family = VG_AF_INET;
        iplen = 4;
    } else if (afi == 2) {
        out->family = VG_AF_INET6;
        iplen = 16;
    } else {
        return VG_BGP_EAFI;
    }
    if (n - off < iplen * 2) return VG_BGP_ETRUNC;
    memcpy(out->peer_ip, b + off, iplen);
    off += iplen;
    memcpy(out->local_ip, b + off, iplen);
    off += iplen;

    out->as4 = as4;
    out->msg = b + off;
    out->msg_len = n - off;
    return VG_BGP_OK;
}

int vg_mrt_parse_peer_index(vg_mrt_reader_t *r, const vg_mrt_rec_t *rec) {
    const uint8_t *b = rec->body;
    size_t n = rec->length;
    if (n < 8) return VG_BGP_ETRUNC;
    size_t off = 4; /* collector BGP ID */
    uint16_t vlen = rd16(b + off);
    off += 2;
    if (n - off < vlen + 2u) return VG_BGP_ETRUNC;
    off += vlen; /* view name */
    uint16_t count = rd16(b + off);
    off += 2;

    r->n_peers = 0;
    for (uint16_t i = 0; i < count; i++) {
        if (n - off < 5) return VG_BGP_ETRUNC;
        uint8_t ptype = b[off++];
        off += 4; /* peer BGP ID */
        bool v6 = (ptype & 0x01) != 0;
        bool as4 = (ptype & 0x02) != 0;
        size_t iplen = v6 ? 16 : 4;
        size_t assz = as4 ? 4 : 2;
        if (n - off < iplen + assz) return VG_BGP_ETRUNC;
        if (r->n_peers >= VG_MRT_MAX_PEERS) return VG_BGP_E2BIG;

        vg_mrt_peer_t *p = &r->peers[r->n_peers++];
        memset(p, 0, sizeof(*p));
        p->family = v6 ? VG_AF_INET6 : VG_AF_INET;
        memcpy(p->addr, b + off, iplen);
        off += iplen;
        p->asn = as4 ? rd32(b + off) : rd16(b + off);
        off += assz;
        ip_to_text(p->family, p->addr, p->text, sizeof(p->text));
    }
    return VG_BGP_OK;
}

int vg_mrt_parse_rib(vg_mrt_reader_t *r, const vg_mrt_rec_t *rec,
                     vg_mrt_rib_cb cb, void *user) {
    vg_family_t fam;
    if (rec->subtype == VG_TDV2_RIB_IPV4_UNICAST) fam = VG_AF_INET;
    else if (rec->subtype == VG_TDV2_RIB_IPV6_UNICAST) fam = VG_AF_INET6;
    else return VG_BGP_EBADTYPE;

    const uint8_t *b = rec->body;
    size_t n = rec->length;
    if (n < 4) return VG_BGP_ETRUNC;
    size_t off = 4; /* sequence number */

    vg_prefix_t prefix;
    int used = vg_nlri_decode(b + off, n - off, fam, &prefix);
    if (used < 0) return used;
    off += (size_t)used;

    if (n - off < 2) return VG_BGP_ETRUNC;
    uint16_t entries = rd16(b + off);
    off += 2;

    static vg_bgp_update_t attrs; /* large; single-threaded reader */
    for (uint16_t i = 0; i < entries; i++) {
        if (n - off < 8) return VG_BGP_ETRUNC;
        uint16_t peer_idx = rd16(b + off);
        double originated = (double)rd32(b + off + 2);
        uint16_t alen = rd16(b + off + 6);
        off += 8;
        if (n - off < alen) return VG_BGP_ETRUNC;
        if (peer_idx >= r->n_peers) return VG_BGP_EATTRLEN;

        memset(&attrs, 0, sizeof(attrs));
        attrs.origin = VG_ORIGIN_UNSET;
        /* TABLE_DUMP_V2 always encodes AS_PATH with 4-octet ASNs */
        int rc = vg_bgp_parse_attrs(b + off, alen, true, true, &attrs);
        if (rc != VG_BGP_OK) return rc;
        off += alen;

        cb(&prefix, &r->peers[peer_idx], originated, &attrs, user);
    }
    return VG_BGP_OK;
}
