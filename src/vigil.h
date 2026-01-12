/*
 * vigil.h — core data model shared by every Vigil component.
 *
 * Every ingest source (MRT replay, RIS Live, stub) normalizes into a
 * vg_update_event_t; detectors and the RIB never care where data came from.
 */
#ifndef VIGIL_H
#define VIGIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Prefix                                                              */
/* ------------------------------------------------------------------ */

typedef enum {
    VG_AF_INET  = 4,
    VG_AF_INET6 = 6,
} vg_family_t;

/* An IP prefix. addr holds the network bytes (4 for v4, 16 for v6);
 * bits beyond len are guaranteed zero after vg_prefix_parse/normalize. */
typedef struct {
    uint8_t family; /* vg_family_t */
    uint8_t len;    /* 0..32 (v4), 0..128 (v6) */
    uint8_t addr[16];
} vg_prefix_t;

#define VG_PREFIX_STRLEN 64 /* enough for v6 addr + "/128" + NUL */

/* Parse "10.0.0.0/8" or "2001:db8::/32". Returns 0 on success, -1 on
 * malformed input (bad address, missing '/', out-of-range length).
 * Host bits beyond the mask are zeroed (normalized). */
int  vg_prefix_parse(const char *s, vg_prefix_t *out);
/* Format into buf (size n). Returns number of chars written, -1 if n
 * is too small. */
int  vg_prefix_format(const vg_prefix_t *p, char *buf, size_t n);
bool vg_prefix_equal(const vg_prefix_t *a, const vg_prefix_t *b);
/* True if `outer` covers `inner` (inner is equal or more-specific). */
bool vg_prefix_covers(const vg_prefix_t *outer, const vg_prefix_t *inner);
/* Zero any bits beyond p->len (in place). */
void vg_prefix_normalize(vg_prefix_t *p);

/* ------------------------------------------------------------------ */
/* AS path                                                             */
/* ------------------------------------------------------------------ */

#define VG_ASPATH_MAX 255

typedef struct {
    uint16_t count;
    uint32_t as[VG_ASPATH_MAX];
    /* True when the rightmost element came from an AS_SET, in which
     * case "the" origin is ambiguous (RFC 4271 aggregation). */
    bool origin_from_set;
} vg_aspath_t;

/* Origin ASN = rightmost AS. Returns 0 when the path is empty. */
uint32_t vg_aspath_origin(const vg_aspath_t *p);
/* "701 3356 15169" — returns chars written or -1 if buf too small. */
int vg_aspath_format(const vg_aspath_t *p, char *buf, size_t n);
/* Parse a space-separated ASN list (test/config convenience). */
int vg_aspath_parse(const char *s, vg_aspath_t *out);

/* ------------------------------------------------------------------ */
/* UpdateEvent — the normalized unit that flows through the pipeline   */
/* ------------------------------------------------------------------ */

typedef enum {
    VG_EV_ANNOUNCE = 0,
    VG_EV_WITHDRAW = 1,
} vg_event_kind_t;

typedef enum {
    VG_ORIGIN_IGP        = 0,
    VG_ORIGIN_EGP        = 1,
    VG_ORIGIN_INCOMPLETE = 2,
    VG_ORIGIN_UNSET      = 255,
} vg_origin_attr_t;

#define VG_MAX_COMMUNITIES 64
#define VG_PEER_STRLEN     64
#define VG_SOURCE_STRLEN   16

typedef struct {
    vg_event_kind_t kind;
    vg_prefix_t     prefix;

    /* Announce-only attributes (zeroed for withdraws) */
    vg_aspath_t path;
    uint8_t     origin_attr;          /* vg_origin_attr_t */
    uint8_t     next_hop_family;      /* 0 = none */
    uint8_t     next_hop[16];
    bool        has_med, has_local_pref;
    uint32_t    med, local_pref;
    uint16_t    n_communities;
    uint32_t    communities[VG_MAX_COMMUNITIES];

    double   timestamp;               /* unix seconds (fractional ok) */
    char     peer[VG_PEER_STRLEN];    /* peer address as text */
    uint32_t peer_asn;
    char     source[VG_SOURCE_STRLEN];/* "stub" | "mrt" | "rislive" */
} vg_event_t;

/* Convenience: origin ASN of an announce (0 for withdraws/empty path) */
uint32_t vg_event_origin(const vg_event_t *e);

/* Every consumer of the normalized stream implements this. */
typedef void (*vg_event_sink_fn)(const vg_event_t *ev, void *user);

/* ------------------------------------------------------------------ */
/* Alert                                                               */
/* ------------------------------------------------------------------ */

typedef enum {
    VG_ALERT_HIJACK       = 0,
    VG_ALERT_SUBPREFIX    = 1,
    VG_ALERT_LEAK         = 2,
    VG_ALERT_RPKI_INVALID = 3,
    VG_ALERT_SPIKE        = 4,
} vg_alert_type_t;

typedef enum {
    VG_SEV_INFO     = 0,
    VG_SEV_WARNING  = 1,
    VG_SEV_CRITICAL = 2,
} vg_severity_t;

#define VG_ALERT_SUMMARY_LEN  256
#define VG_ALERT_EVIDENCE_LEN 512

typedef struct {
    int64_t         id;        /* assigned by the alert store, 0 before */
    vg_alert_type_t type;
    vg_severity_t   severity;
    double          timestamp;
    vg_prefix_t     prefix;
    uint32_t        expected_asn; /* semantics depend on type; 0 = n/a */
    uint32_t        observed_asn;
    char            peer[VG_PEER_STRLEN];
    char            summary[VG_ALERT_SUMMARY_LEN];
    char            evidence[VG_ALERT_EVIDENCE_LEN]; /* JSON blob */
} vg_alert_t;

const char *vg_alert_type_str(vg_alert_type_t t);
const char *vg_severity_str(vg_severity_t s);

#endif /* VIGIL_H */
