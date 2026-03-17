/*
 * RIB: per-peer Adj-RIB-In keyed by prefix, with a binary trie per
 * address family for more-specific / covering-prefix queries and a
 * bounded per-prefix history ring.
 *
 * Thread model: vg_rib_apply takes a write lock; all queries take a
 * read lock. Query callbacks run under the read lock — do not call
 * back into the RIB from a callback.
 */
#ifndef VIGIL_RIB_H
#define VIGIL_RIB_H

#include "../vigil.h"

#define VG_RIB_HISTORY 32 /* retained changes per prefix */

typedef struct {
    char        peer[VG_PEER_STRLEN];
    uint32_t    peer_asn;
    vg_aspath_t path;
    uint8_t     origin_attr;
    uint8_t     next_hop_family;
    uint8_t     next_hop[16];
    double      first_seen, last_updated;
} vg_rib_route_t;

typedef struct {
    double          ts;
    vg_event_kind_t kind;
    uint32_t        origin_asn; /* 0 for withdraws */
    uint32_t        peer_asn;
    char            peer[VG_PEER_STRLEN];
} vg_rib_change_t;

typedef struct {
    uint64_t prefixes;       /* prefix entries (incl. fully withdrawn) */
    uint64_t routes;         /* live (prefix, peer) routes */
    uint64_t events_applied;
    uint64_t mem_bytes;      /* approximate heap usage */
} vg_rib_stats_t;

typedef struct vg_rib vg_rib_t;

vg_rib_t *vg_rib_new(void);
void      vg_rib_free(vg_rib_t *rib);

/* Apply one normalized event. Announces upsert the (prefix, peer)
 * route; withdraws remove it (the prefix entry and its history are
 * retained so "previously originated by" remains answerable). */
void vg_rib_apply(vg_rib_t *rib, const vg_event_t *ev);
/* vg_event_sink_fn adapter (user = vg_rib_t*) */
void vg_rib_sink(const vg_event_t *ev, void *user);

typedef void (*vg_rib_route_cb)(const vg_prefix_t *prefix,
                                const vg_rib_route_t *route, void *user);
typedef void (*vg_rib_change_cb)(const vg_rib_change_t *change, void *user);

/* Routes currently held for exactly this prefix. Returns count. */
int vg_rib_lookup(vg_rib_t *rib, const vg_prefix_t *p, vg_rib_route_cb cb,
                  void *user);
/* Change history (oldest first). Returns count. */
int vg_rib_history(vg_rib_t *rib, const vg_prefix_t *p, vg_rib_change_cb cb,
                   void *user);
/* All live routes for prefixes strictly more specific than p. */
int vg_rib_more_specifics(vg_rib_t *rib, const vg_prefix_t *p,
                          vg_rib_route_cb cb, void *user);
/* All live routes for prefixes that cover p (equal or less specific). */
int vg_rib_covering(vg_rib_t *rib, const vg_prefix_t *p, vg_rib_route_cb cb,
                    void *user);
/* All live routes whose origin AS is `asn` (full scan). */
int vg_rib_by_origin(vg_rib_t *rib, uint32_t asn, vg_rib_route_cb cb,
                     void *user);

/* Dominant current origin for a prefix: the origin ASN announced by
 * the most peers (ties broken by lowest ASN). 0 if no live routes. */
uint32_t vg_rib_origin_of(vg_rib_t *rib, const vg_prefix_t *p);

void vg_rib_stats(vg_rib_t *rib, vg_rib_stats_t *out);

#endif
