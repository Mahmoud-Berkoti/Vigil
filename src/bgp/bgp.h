/*
 * BGP-4 wire format (RFC 4271) + Multiprotocol extensions (RFC 4760)
 * + 4-octet ASNs (RFC 6793).
 *
 * Parsing rules: never read past the supplied buffer, never crash on
 * arbitrary input, return a specific error for malformed data. This is
 * a monitor, so unknown OPTIONAL attributes are skipped (recorded in
 * unknown_attrs); structurally broken messages are rejected.
 */
#ifndef VIGIL_BGP_H
#define VIGIL_BGP_H

#include "../vigil.h"

#define VG_BGP_HEADER_LEN 19
#define VG_BGP_MAX_LEN    4096

typedef enum {
    VG_BGP_OPEN         = 1,
    VG_BGP_UPDATE       = 2,
    VG_BGP_NOTIFICATION = 3,
    VG_BGP_KEEPALIVE    = 4,
} vg_bgp_msg_type_t;

/* Path attribute type codes we understand */
enum {
    VG_ATTR_ORIGIN           = 1,
    VG_ATTR_AS_PATH          = 2,
    VG_ATTR_NEXT_HOP         = 3,
    VG_ATTR_MED              = 4,
    VG_ATTR_LOCAL_PREF       = 5,
    VG_ATTR_ATOMIC_AGGREGATE = 6,
    VG_ATTR_AGGREGATOR       = 7,
    VG_ATTR_COMMUNITIES      = 8,
    VG_ATTR_MP_REACH_NLRI    = 14,
    VG_ATTR_MP_UNREACH_NLRI  = 15,
    VG_ATTR_AS4_PATH         = 17,
    VG_ATTR_AS4_AGGREGATOR   = 18,
    VG_ATTR_LARGE_COMMUNITIES= 32,
};

/* Attribute flag bits */
enum {
    VG_ATTRF_OPTIONAL   = 0x80,
    VG_ATTRF_TRANSITIVE = 0x40,
    VG_ATTRF_PARTIAL    = 0x20,
    VG_ATTRF_EXTLEN     = 0x10,
};

/* Parse errors (negative return values) */
enum {
    VG_BGP_OK          = 0,
    VG_BGP_EBADMARKER  = -1, /* header marker not all-ones */
    VG_BGP_EBADLEN     = -2, /* length field out of [19,4096] or > buffer */
    VG_BGP_EBADTYPE    = -3, /* unknown message type */
    VG_BGP_ETRUNC      = -4, /* ran out of bytes mid-structure */
    VG_BGP_EATTRLEN    = -5, /* attribute length inconsistent */
    VG_BGP_EPREFIXLEN  = -6, /* NLRI prefix length > 32/128 */
    VG_BGP_ESEGTYPE    = -7, /* AS_PATH segment type invalid */
    VG_BGP_EAFI        = -8, /* unsupported AFI/SAFI in MP attrs */
    VG_BGP_E2BIG       = -9, /* more routes/ASNs than we can hold */
    VG_BGP_EMISSING    = -10,/* announce without mandatory attributes */
};

const char *vg_bgp_strerror(int err);

typedef struct {
    uint16_t len;  /* total message length incl. 19-byte header */
    uint8_t  type; /* vg_bgp_msg_type_t */
} vg_bgp_hdr_t;

/* Validates marker, bounds-checks length, checks type; needs n >= 19.
 * Length is also validated against the per-type minimum. */
int vg_bgp_parse_header(const uint8_t *buf, size_t n, vg_bgp_hdr_t *out);

/* ------------------------------------------------------------------ */
/* OPEN                                                                */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t  version;
    uint16_t my_as;       /* 2-octet field; AS_TRANS (23456) if 4-byte */
    uint16_t hold_time;
    uint32_t bgp_id;
    bool     cap_as4;     /* capability 65 seen */
    uint32_t as4;         /* 4-octet ASN from capability 65 */
    bool     cap_mp_ipv4, cap_mp_ipv6; /* capability 1, AFI 1/2 SAFI 1 */
} vg_bgp_open_t;

/* payload = message bytes after the 19-byte header */
int vg_bgp_parse_open(const uint8_t *payload, size_t n, vg_bgp_open_t *out);

/* ------------------------------------------------------------------ */
/* UPDATE                                                              */
/* ------------------------------------------------------------------ */

#define VG_BGP_MAX_ROUTES 4096 /* /0 prefixes encode in 1 byte each */

typedef struct {
    uint16_t    n_withdrawn;
    vg_prefix_t withdrawn[VG_BGP_MAX_ROUTES]; /* v4 (classic field) */
    uint16_t    n_nlri;
    vg_prefix_t nlri[VG_BGP_MAX_ROUTES];      /* v4 (classic field) */

    /* Path attributes */
    bool        has_path;
    vg_aspath_t path;          /* AS4_PATH-merged when applicable */
    uint8_t     origin;        /* vg_origin_attr_t; VG_ORIGIN_UNSET */
    bool        has_next_hop;
    uint8_t     next_hop[4];
    bool        has_med, has_local_pref;
    uint32_t    med, local_pref;
    uint16_t    n_communities;
    uint32_t    communities[VG_MAX_COMMUNITIES];

    /* MP-BGP (RFC 4760); we support AFI v4/v6, SAFI unicast */
    bool        has_mp_reach;
    uint8_t     mp_af;              /* vg_family_t */
    uint8_t     mp_next_hop[16];
    uint8_t     mp_next_hop_len;
    uint16_t    n_mp_nlri;
    vg_prefix_t mp_nlri[VG_BGP_MAX_ROUTES];
    bool        has_mp_unreach;
    uint8_t     mp_unreach_af;
    uint16_t    n_mp_unreach;
    vg_prefix_t mp_unreach[VG_BGP_MAX_ROUTES];

    uint16_t    n_unknown_attrs;    /* skipped optional attrs */
} vg_bgp_update_t;

/* Parse an UPDATE payload (bytes after the header). `as4` selects
 * 2- vs 4-octet encoding of AS_PATH (negotiated / known from MRT).
 * Struct is ~large: heap- or statically allocate it, memset not
 * required (fully initialized on entry). */
int vg_bgp_parse_update(const uint8_t *payload, size_t n, bool as4,
                        vg_bgp_update_t *out);

/* Serialize a full UPDATE message (header included) for tests and
 * synthetic fixtures. Returns total length or negative error. */
int vg_bgp_write_update(const vg_bgp_update_t *u, bool as4, uint8_t *buf,
                        size_t n);

/* ------------------------------------------------------------------ */
/* Shared low-level helpers (pathattr.c / nlri.c)                      */
/* ------------------------------------------------------------------ */

/* Decode one NLRI prefix at buf[0..n): 1 length byte + ceil(len/8)
 * bytes. Returns bytes consumed or negative error. */
int vg_nlri_decode(const uint8_t *buf, size_t n, vg_family_t family,
                   vg_prefix_t *out);
/* Encode; returns bytes written or negative error. */
int vg_nlri_encode(const vg_prefix_t *p, uint8_t *buf, size_t n);

/* Parse an AS_PATH attribute value (segments) into a flat path.
 * asn_size is 2 or 4. */
int vg_aspath_decode(const uint8_t *buf, size_t n, int asn_size,
                     vg_aspath_t *out);

#endif
