#include "mrtfile.h"

#include "../bgp/bgp.h"
#include "../core/log.h"
#include "../mrt/mrt.h"
#include "../util/hashset.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    vg_event_sink_fn sink;
    void            *user;
    vg_mrt_stats_t   st;
    vg_hashset_t     prefixes; /* key: vg_prefix_t (family+len+addr) */
    vg_hashset_t     origins;  /* key: uint32_t */
} replay_ctx_t;

/* key must be fully deterministic: rebuild from the canonical fields */
static void note_prefix(replay_ctx_t *c, const vg_prefix_t *p) {
    uint8_t key[18];
    key[0] = p->family;
    key[1] = p->len;
    memcpy(key + 2, p->addr, 16);
    vg_hashset_add(&c->prefixes, key);
}

static void emit(replay_ctx_t *c, vg_event_t *ev) {
    note_prefix(c, &ev->prefix);
    if (ev->kind == VG_EV_ANNOUNCE) {
        c->st.announces++;
        uint32_t origin = vg_event_origin(ev);
        if (origin) vg_hashset_add(&c->origins, &origin);
    } else {
        c->st.withdraws++;
    }
    c->sink(ev, c->user);
}

/* Fill announce-only attribute fields from parsed BGP attributes. */
static void fill_attrs(vg_event_t *ev, const vg_bgp_update_t *u) {
    ev->path = u->path;
    ev->origin_attr = u->origin;
    if (u->has_next_hop) {
        ev->next_hop_family = VG_AF_INET;
        memcpy(ev->next_hop, u->next_hop, 4);
    } else if (u->has_mp_reach && u->mp_next_hop_len > 0) {
        ev->next_hop_family = u->mp_next_hop_len == 4 ? VG_AF_INET : VG_AF_INET6;
        memcpy(ev->next_hop, u->mp_next_hop, u->mp_next_hop_len);
    }
    ev->has_med = u->has_med;
    ev->med = u->med;
    ev->has_local_pref = u->has_local_pref;
    ev->local_pref = u->local_pref;
    ev->n_communities = u->n_communities;
    memcpy(ev->communities, u->communities,
           (size_t)u->n_communities * sizeof(uint32_t));
}

static void base_event(vg_event_t *ev, double ts, const char *peer,
                       uint32_t peer_asn) {
    memset(ev, 0, sizeof(*ev));
    ev->timestamp = ts;
    ev->origin_attr = VG_ORIGIN_UNSET;
    snprintf(ev->peer, sizeof(ev->peer), "%s", peer);
    ev->peer_asn = peer_asn;
    snprintf(ev->source, sizeof(ev->source), "mrt");
}

static void handle_bgp4mp(replay_ctx_t *c, const vg_mrt_rec_t *rec) {
    vg_mrt_bgp4mp_t m;
    if (vg_mrt_parse_bgp4mp(rec, &m) != VG_BGP_OK) {
        c->st.skipped_records++; /* state changes etc. */
        return;
    }

    vg_bgp_hdr_t hdr;
    if (vg_bgp_parse_header(m.msg, m.msg_len, &hdr) != VG_BGP_OK) {
        c->st.parse_errors++;
        return;
    }
    if (hdr.type != VG_BGP_UPDATE) {
        c->st.skipped_records++;
        return;
    }

    static vg_bgp_update_t u;
    int rc = vg_bgp_parse_update(m.msg + VG_BGP_HEADER_LEN,
                                 (size_t)hdr.len - VG_BGP_HEADER_LEN, m.as4, &u);
    if (rc != VG_BGP_OK) {
        c->st.parse_errors++;
        vg_log(VG_LOG_DEBUG, "mrt", "malformed update skipped: %s",
               vg_bgp_strerror(rc));
        return;
    }
    c->st.bgp_updates++;

    char peer[VG_PEER_STRLEN];
    if (!inet_ntop(m.family == VG_AF_INET ? AF_INET : AF_INET6, m.peer_ip,
                   peer, sizeof(peer)))
        snprintf(peer, sizeof(peer), "?");

    vg_event_t ev;
    for (uint16_t i = 0; i < u.n_withdrawn; i++) {
        base_event(&ev, rec->timestamp, peer, m.peer_as);
        ev.kind = VG_EV_WITHDRAW;
        ev.prefix = u.withdrawn[i];
        emit(c, &ev);
    }
    for (uint16_t i = 0; i < u.n_mp_unreach; i++) {
        base_event(&ev, rec->timestamp, peer, m.peer_as);
        ev.kind = VG_EV_WITHDRAW;
        ev.prefix = u.mp_unreach[i];
        emit(c, &ev);
    }
    for (uint16_t i = 0; i < u.n_nlri; i++) {
        base_event(&ev, rec->timestamp, peer, m.peer_as);
        ev.kind = VG_EV_ANNOUNCE;
        ev.prefix = u.nlri[i];
        fill_attrs(&ev, &u);
        emit(c, &ev);
    }
    for (uint16_t i = 0; i < u.n_mp_nlri; i++) {
        base_event(&ev, rec->timestamp, peer, m.peer_as);
        ev.kind = VG_EV_ANNOUNCE;
        ev.prefix = u.mp_nlri[i];
        fill_attrs(&ev, &u);
        emit(c, &ev);
    }
}

static void rib_entry_cb(const vg_prefix_t *prefix, const vg_mrt_peer_t *peer,
                         double originated, const vg_bgp_update_t *attrs,
                         void *user) {
    replay_ctx_t *c = user;
    c->st.rib_entries++;

    vg_event_t ev;
    base_event(&ev, originated, peer->text, peer->asn);
    ev.kind = VG_EV_ANNOUNCE;
    ev.prefix = *prefix;
    fill_attrs(&ev, attrs);
    emit(c, &ev);
}

int vg_mrt_replay(const char *path, double speed, vg_event_sink_fn sink,
                  void *user, vg_mrt_stats_t *stats_out) {
    vg_mrt_reader_t r;
    if (vg_mrt_open(&r, path) != 0) {
        vg_log(VG_LOG_ERROR, "mrt", "cannot open %s", path);
        return -1;
    }

    replay_ctx_t c;
    memset(&c, 0, sizeof(c));
    c.sink = sink;
    c.user = user;
    if (vg_hashset_init(&c.prefixes, 18) != 0 ||
        vg_hashset_init(&c.origins, sizeof(uint32_t)) != 0) {
        vg_mrt_close(&r);
        return -1;
    }

    double prev_ts = 0;
    vg_mrt_rec_t rec;
    int rc;
    while ((rc = vg_mrt_next(&r, &rec)) == 1) {
        c.st.records++;

        if (speed > 0 && prev_ts > 0 && rec.timestamp > prev_ts) {
            double delay = (rec.timestamp - prev_ts) / speed;
            if (delay > 0 && delay < 60)
                usleep((useconds_t)(delay * 1e6));
        }
        prev_ts = rec.timestamp;

        switch (rec.type) {
        case VG_MRT_BGP4MP:
        case VG_MRT_BGP4MP_ET:
            handle_bgp4mp(&c, &rec);
            break;
        case VG_MRT_TABLE_DUMP_V2:
            if (rec.subtype == VG_TDV2_PEER_INDEX_TABLE) {
                if (vg_mrt_parse_peer_index(&r, &rec) != VG_BGP_OK)
                    c.st.parse_errors++;
            } else if (rec.subtype == VG_TDV2_RIB_IPV4_UNICAST ||
                       rec.subtype == VG_TDV2_RIB_IPV6_UNICAST) {
                if (vg_mrt_parse_rib(&r, &rec, rib_entry_cb, &c) != VG_BGP_OK)
                    c.st.parse_errors++;
            } else {
                c.st.skipped_records++;
            }
            break;
        default:
            c.st.skipped_records++;
            break;
        }
    }

    c.st.unique_prefixes = vg_hashset_count(&c.prefixes);
    c.st.unique_origins = vg_hashset_count(&c.origins);

    vg_log(VG_LOG_INFO, "mrt",
           "replay %s: records=%llu updates=%llu rib_entries=%llu "
           "announces=%llu withdraws=%llu prefixes=%llu origins=%llu "
           "errors=%llu skipped=%llu",
           path, (unsigned long long)c.st.records,
           (unsigned long long)c.st.bgp_updates,
           (unsigned long long)c.st.rib_entries,
           (unsigned long long)c.st.announces,
           (unsigned long long)c.st.withdraws,
           (unsigned long long)c.st.unique_prefixes,
           (unsigned long long)c.st.unique_origins,
           (unsigned long long)c.st.parse_errors,
           (unsigned long long)c.st.skipped_records);

    if (stats_out) *stats_out = c.st;
    vg_hashset_free(&c.prefixes);
    vg_hashset_free(&c.origins);
    vg_mrt_close(&r);
    return rc < 0 ? -1 : 0;
}
