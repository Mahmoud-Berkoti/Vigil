/*
 * MRT format (RFC 6396): TABLE_DUMP_V2 RIB snapshots and BGP4MP
 * update streams, as published by RouteViews and RIPE RIS.
 */
#ifndef VIGIL_MRT_H
#define VIGIL_MRT_H

#include "../bgp/bgp.h"
#include "../vigil.h"

#include <stdio.h>

/* MRT record types we care about */
enum {
    VG_MRT_TABLE_DUMP_V2 = 13,
    VG_MRT_BGP4MP        = 16,
    VG_MRT_BGP4MP_ET     = 17,
};

/* BGP4MP subtypes */
enum {
    VG_BGP4MP_STATE_CHANGE      = 0,
    VG_BGP4MP_MESSAGE           = 1,
    VG_BGP4MP_MESSAGE_AS4       = 4,
    VG_BGP4MP_STATE_CHANGE_AS4  = 5,
    VG_BGP4MP_MESSAGE_LOCAL     = 6,
    VG_BGP4MP_MESSAGE_AS4_LOCAL = 7,
};

/* TABLE_DUMP_V2 subtypes */
enum {
    VG_TDV2_PEER_INDEX_TABLE   = 1,
    VG_TDV2_RIB_IPV4_UNICAST   = 2,
    VG_TDV2_RIB_IPV4_MULTICAST = 3,
    VG_TDV2_RIB_IPV6_UNICAST   = 4,
    VG_TDV2_RIB_IPV6_MULTICAST = 5,
};

#define VG_MRT_MAX_BODY (1u << 20) /* sanity cap on record length */
#define VG_MRT_MAX_PEERS 1024      /* peer index table capacity */

typedef struct {
    double   timestamp;  /* seconds (+ microseconds for _ET types) */
    uint16_t type, subtype;
    uint32_t length;     /* body length (after the 12-byte header) */
    const uint8_t *body; /* valid until the next vg_mrt_next() call */
} vg_mrt_rec_t;

typedef struct {
    uint32_t asn;
    uint8_t  family;   /* vg_family_t */
    uint8_t  addr[16];
    char     text[VG_PEER_STRLEN];
} vg_mrt_peer_t;

typedef struct {
    FILE    *f;
    uint8_t *buf;
    size_t   cap;
    /* PEER_INDEX_TABLE state for TABLE_DUMP_V2 files */
    int           n_peers;
    vg_mrt_peer_t peers[VG_MRT_MAX_PEERS];
    uint64_t      records_read;
} vg_mrt_reader_t;

/* Returns 0 ok, -1 on open failure. */
int  vg_mrt_open(vg_mrt_reader_t *r, const char *path);
void vg_mrt_close(vg_mrt_reader_t *r);
/* 1 = record produced, 0 = clean EOF, negative = corrupt file. */
int  vg_mrt_next(vg_mrt_reader_t *r, vg_mrt_rec_t *rec);

/* Parsed BGP4MP_MESSAGE(_AS4) wrapper */
typedef struct {
    uint32_t peer_as, local_as;
    uint8_t  family; /* address family of the peer/local IPs */
    uint8_t  peer_ip[16], local_ip[16];
    bool     as4;    /* 4-octet encoding inside the BGP message */
    const uint8_t *msg; /* full BGP message incl. 19-byte header */
    size_t   msg_len;
} vg_mrt_bgp4mp_t;

int vg_mrt_parse_bgp4mp(const vg_mrt_rec_t *rec, vg_mrt_bgp4mp_t *out);

/* Parse a PEER_INDEX_TABLE into the reader's peer array. */
int vg_mrt_parse_peer_index(vg_mrt_reader_t *r, const vg_mrt_rec_t *rec);

/* Iterate a TABLE_DUMP_V2 RIB record: calls cb once per RIB entry with
 * the parsed attributes. Returns 0 or a negative parse error. */
typedef void (*vg_mrt_rib_cb)(const vg_prefix_t *prefix,
                              const vg_mrt_peer_t *peer,
                              double originated,
                              const vg_bgp_update_t *attrs, void *user);
int vg_mrt_parse_rib(vg_mrt_reader_t *r, const vg_mrt_rec_t *rec,
                     vg_mrt_rib_cb cb, void *user);

#endif
