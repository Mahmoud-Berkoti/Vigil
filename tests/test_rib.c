#include "../src/ingest/mrtfile.h"
#include "../src/rib/rib.h"
#include "test.h"

#include <unistd.h>

static vg_event_t mk_announce(const char *pfx, const char *path,
                              const char *peer, uint32_t peer_asn, double ts) {
    vg_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.kind = VG_EV_ANNOUNCE;
    vg_prefix_parse(pfx, &ev.prefix);
    vg_aspath_parse(path, &ev.path);
    ev.origin_attr = VG_ORIGIN_IGP;
    ev.timestamp = ts;
    snprintf(ev.peer, sizeof(ev.peer), "%s", peer);
    ev.peer_asn = peer_asn;
    snprintf(ev.source, sizeof(ev.source), "test");
    return ev;
}

static vg_event_t mk_withdraw(const char *pfx, const char *peer,
                              uint32_t peer_asn, double ts) {
    vg_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.kind = VG_EV_WITHDRAW;
    vg_prefix_parse(pfx, &ev.prefix);
    ev.timestamp = ts;
    snprintf(ev.peer, sizeof(ev.peer), "%s", peer);
    ev.peer_asn = peer_asn;
    return ev;
}

/* collect prefixes seen by a route callback */
#define MAX_SEEN 128
static char seen[MAX_SEEN][VG_PREFIX_STRLEN];
static int n_seen;
static void collect(const vg_prefix_t *p, const vg_rib_route_t *r, void *u) {
    (void)r;
    (void)u;
    if (n_seen < MAX_SEEN)
        vg_prefix_format(p, seen[n_seen++], VG_PREFIX_STRLEN);
}
static bool saw(const char *pfx) {
    for (int i = 0; i < n_seen; i++)
        if (strcmp(seen[i], pfx) == 0) return true;
    return false;
}

static int n_changes;
static vg_rib_change_t last_change;
static void collect_change(const vg_rib_change_t *c, void *u) {
    (void)u;
    n_changes++;
    last_change = *c;
}

int main(void) {
    vg_rib_t *rib = vg_rib_new();
    CHECK(rib != NULL);

    vg_event_t ev;
    vg_prefix_t p;

    /* two peers announce the same prefix, same origin */
    ev = mk_announce("192.0.2.0/24", "6939 15169", "p1", 6939, 100);
    vg_rib_apply(rib, &ev);
    ev = mk_announce("192.0.2.0/24", "3356 15169", "p2", 3356, 101);
    vg_rib_apply(rib, &ev);
    /* third peer says a different origin */
    ev = mk_announce("192.0.2.0/24", "1299 64666", "p3", 1299, 102);
    vg_rib_apply(rib, &ev);

    vg_prefix_parse("192.0.2.0/24", &p);
    CHECK_EQ_INT(vg_rib_lookup(rib, &p, NULL, NULL), 3);
    /* majority origin wins */
    CHECK_EQ_INT(vg_rib_origin_of(rib, &p), 15169);

    /* re-announce from p1 updates in place (no duplicate route) */
    ev = mk_announce("192.0.2.0/24", "6939 174 15169", "p1", 6939, 103);
    vg_rib_apply(rib, &ev);
    CHECK_EQ_INT(vg_rib_lookup(rib, &p, NULL, NULL), 3);

    /* withdraw from p3 removes only p3's route */
    ev = mk_withdraw("192.0.2.0/24", "p3", 1299, 104);
    vg_rib_apply(rib, &ev);
    CHECK_EQ_INT(vg_rib_lookup(rib, &p, NULL, NULL), 2);
    CHECK_EQ_INT(vg_rib_origin_of(rib, &p), 15169);

    /* withdraw for a peer with no route is a no-op (no history entry) */
    vg_rib_history(rib, &p, collect_change, NULL);
    int hist_before = n_changes;
    n_changes = 0;
    ev = mk_withdraw("192.0.2.0/24", "p9", 9999, 105);
    vg_rib_apply(rib, &ev);
    vg_rib_history(rib, &p, collect_change, NULL);
    CHECK_EQ_INT(n_changes, hist_before);

    /* withdraw everything: entry + history survive with 0 live routes */
    ev = mk_withdraw("192.0.2.0/24", "p1", 6939, 106);
    vg_rib_apply(rib, &ev);
    ev = mk_withdraw("192.0.2.0/24", "p2", 3356, 107);
    vg_rib_apply(rib, &ev);
    CHECK_EQ_INT(vg_rib_lookup(rib, &p, NULL, NULL), 0);
    CHECK_EQ_INT(vg_rib_origin_of(rib, &p), 0);
    n_changes = 0;
    CHECK(vg_rib_history(rib, &p, collect_change, NULL) > 0);
    CHECK_EQ_INT((int)last_change.kind, (int)VG_EV_WITHDRAW);
    CHECK(last_change.ts == 107.0);

    /* more-specifics / covering */
    ev = mk_announce("10.0.0.0/8", "1 2", "p1", 1, 200);
    vg_rib_apply(rib, &ev);
    ev = mk_announce("10.1.0.0/16", "1 3", "p1", 1, 201);
    vg_rib_apply(rib, &ev);
    ev = mk_announce("10.1.2.0/24", "1 4", "p1", 1, 202);
    vg_rib_apply(rib, &ev);
    ev = mk_announce("10.128.0.0/9", "1 5", "p1", 1, 203);
    vg_rib_apply(rib, &ev);
    ev = mk_announce("11.0.0.0/8", "1 6", "p1", 1, 204);
    vg_rib_apply(rib, &ev);

    vg_prefix_parse("10.0.0.0/8", &p);
    n_seen = 0;
    CHECK_EQ_INT(vg_rib_more_specifics(rib, &p, collect, NULL), 3);
    CHECK(saw("10.1.0.0/16") && saw("10.1.2.0/24") && saw("10.128.0.0/9"));
    CHECK(!saw("10.0.0.0/8"));
    CHECK(!saw("11.0.0.0/8"));

    vg_prefix_parse("10.1.2.0/24", &p);
    n_seen = 0;
    CHECK_EQ_INT(vg_rib_covering(rib, &p, collect, NULL), 3);
    CHECK(saw("10.0.0.0/8") && saw("10.1.0.0/16") && saw("10.1.2.0/24"));

    /* by-origin scan */
    n_seen = 0;
    CHECK_EQ_INT(vg_rib_by_origin(rib, 4, collect, NULL), 1);
    CHECK(saw("10.1.2.0/24"));

    /* v6 trie is independent */
    ev = mk_announce("2001:db8::/32", "1 7", "p1", 1, 300);
    vg_rib_apply(rib, &ev);
    ev = mk_announce("2001:db8:1::/48", "1 8", "p1", 1, 301);
    vg_rib_apply(rib, &ev);
    vg_prefix_parse("2001:db8::/32", &p);
    n_seen = 0;
    CHECK_EQ_INT(vg_rib_more_specifics(rib, &p, collect, NULL), 1);
    CHECK(saw("2001:db8:1::/48"));

    vg_rib_stats_t st;
    vg_rib_stats(rib, &st);
    CHECK(st.prefixes >= 8);
    CHECK(st.routes >= 7);
    CHECK(st.mem_bytes > 0);
    vg_rib_free(rib);

    /* ---- real fixture replay into the RIB ---- */
    if (access("data/fixtures/updates-sample.mrt", R_OK) == 0) {
        rib = vg_rib_new();
        vg_mrt_stats_t mst;
        CHECK_EQ_INT(vg_mrt_replay("data/fixtures/updates-sample.mrt", 0,
                                   vg_rib_sink, rib, &mst), 0);
        vg_rib_stats(rib, &st);
        CHECK_EQ_INT((int)st.events_applied,
                     (int)(mst.announces + mst.withdraws));
        CHECK(st.prefixes > 0 && st.prefixes <= mst.unique_prefixes);
        CHECK(st.routes > 0);
        /* memory stays proportional: < 3KB per prefix on this sample */
        CHECK(st.mem_bytes < st.prefixes * 3072 + (1 << 20));
        vg_rib_free(rib);
    }

    TEST_MAIN_END();
}
