#include "../src/detect/detect.h"
#include "../src/ingest/mrtfile.h"
#include "test.h"

#include <unistd.h>

/* ---- alert capture ------------------------------------------------ */

#define MAX_AL 64
static vg_alert_t alerts[MAX_AL];
static int n_alerts;
static void capture_alert(const vg_alert_t *a, void *user) {
    (void)user;
    if (n_alerts < MAX_AL) alerts[n_alerts++] = *a;
}
static int count_type(vg_alert_type_t t) {
    int n = 0;
    for (int i = 0; i < n_alerts; i++)
        if (alerts[i].type == t) n++;
    return n;
}
static const vg_alert_t *first_of(vg_alert_type_t t) {
    for (int i = 0; i < n_alerts; i++)
        if (alerts[i].type == t) return &alerts[i];
    return NULL;
}

/* ---- event builders ----------------------------------------------- */

static vg_event_t announce(const char *pfx, const char *path,
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

static vg_event_t withdraw(const char *pfx, const char *peer,
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

static void feed(vg_engine_t *e, vg_event_t ev) { vg_engine_event(e, &ev); }

/* ------------------------------------------------------------------ */

static void test_origin_hijack_watchlist(void) {
    vg_config_t cfg;
    vg_config_defaults(&cfg);
    cfg.n_watch = 1;
    vg_prefix_parse("192.0.2.0/24", &cfg.watch_prefix[0]);
    cfg.watch_origin[0] = 64500;

    vg_rib_t *rib = vg_rib_new();
    vg_engine_t *e = vg_engine_new(&cfg, rib, capture_alert, NULL);
    n_alerts = 0;

    /* clean traffic: expected origin, repeated, plus withdraw */
    feed(e, announce("192.0.2.0/24", "6939 3356 64500", "p1", 6939, 1000));
    feed(e, announce("192.0.2.0/24", "1299 64500", "p2", 1299, 1010));
    feed(e, withdraw("192.0.2.0/24", "p2", 1299, 1020));
    feed(e, announce("192.0.2.0/24", "1299 64500", "p2", 1299, 1030));
    CHECK_EQ_INT(n_alerts, 0); /* zero false positives */

    /* hijack: different origin */
    feed(e, announce("192.0.2.0/24", "6939 64666", "p1", 6939, 1100));
    CHECK_EQ_INT(count_type(VG_ALERT_HIJACK), 1);
    const vg_alert_t *a = first_of(VG_ALERT_HIJACK);
    CHECK_EQ_INT((int)a->severity, (int)VG_SEV_CRITICAL);
    CHECK_EQ_INT(a->expected_asn, 64500);
    CHECK_EQ_INT(a->observed_asn, 64666);
    CHECK(a->timestamp == 1100.0);
    CHECK(strstr(a->summary, "64666") != NULL);
    CHECK(strstr(a->evidence, "\"expected_origin\":64500") != NULL);

    /* same hijack within cooldown: suppressed */
    feed(e, announce("192.0.2.0/24", "6939 64666", "p1", 6939, 1150));
    CHECK_EQ_INT(count_type(VG_ALERT_HIJACK), 1);
    vg_engine_stats_t st;
    vg_engine_stats(e, &st);
    CHECK_EQ_INT((int)st.suppressed, 1);

    /* after cooldown: fires again */
    feed(e, announce("192.0.2.0/24", "6939 64666", "p1", 6939, 1500));
    CHECK_EQ_INT(count_type(VG_ALERT_HIJACK), 2);

    vg_engine_free(e);
    vg_rib_free(rib);
}

static void test_learned_baseline(void) {
    vg_config_t cfg;
    vg_config_defaults(&cfg);
    cfg.baseline_window = 300;

    vg_rib_t *rib = vg_rib_new();
    vg_engine_t *e = vg_engine_new(&cfg, rib, capture_alert, NULL);
    n_alerts = 0;

    /* two origins observed inside the window: legitimate MOAS */
    feed(e, announce("198.51.100.0/24", "1 100", "p1", 1, 0));
    feed(e, announce("198.51.100.0/24", "2 200", "p2", 2, 100));
    /* window passes; the same two origins keep announcing */
    feed(e, announce("198.51.100.0/24", "1 100", "p1", 1, 400));
    feed(e, announce("198.51.100.0/24", "2 200", "p2", 2, 410));
    CHECK_EQ_INT(n_alerts, 0);

    /* a third origin after lock: hijack (warning: not watchlisted) */
    feed(e, announce("198.51.100.0/24", "3 300", "p3", 3, 500));
    CHECK_EQ_INT(count_type(VG_ALERT_HIJACK), 1);
    CHECK_EQ_INT((int)first_of(VG_ALERT_HIJACK)->severity, (int)VG_SEV_WARNING);

    /* baseline query API */
    vg_prefix_t p;
    vg_prefix_parse("198.51.100.0/24", &p);
    const vg_baseline_entry_t *b = vg_engine_baseline(e, &p);
    CHECK(b && b->locked && b->n_origins == 2);

    vg_engine_free(e);
    vg_rib_free(rib);
}

static void test_subprefix_hijack(void) {
    vg_config_t cfg;
    vg_config_defaults(&cfg);
    cfg.n_watch = 1;
    vg_prefix_parse("10.10.0.0/16", &cfg.watch_prefix[0]);
    cfg.watch_origin[0] = 64500;

    vg_rib_t *rib = vg_rib_new();
    vg_engine_t *e = vg_engine_new(&cfg, rib, capture_alert, NULL);
    n_alerts = 0;

    /* covering prefix announced normally */
    feed(e, announce("10.10.0.0/16", "6939 64500", "p1", 6939, 1000));
    /* owner announces its own more-specific: fine */
    feed(e, announce("10.10.5.0/24", "6939 64500", "p1", 6939, 1010));
    CHECK_EQ_INT(n_alerts, 0);

    /* attacker announces a more-specific with a different origin */
    feed(e, announce("10.10.99.0/24", "1299 64666", "p2", 1299, 1100));
    CHECK_EQ_INT(count_type(VG_ALERT_SUBPREFIX), 1);
    const vg_alert_t *a = first_of(VG_ALERT_SUBPREFIX);
    CHECK_EQ_INT((int)a->severity, (int)VG_SEV_CRITICAL);
    CHECK_EQ_INT(a->expected_asn, 64500);
    CHECK_EQ_INT(a->observed_asn, 64666);
    char buf[VG_PREFIX_STRLEN];
    vg_prefix_format(&a->prefix, buf, sizeof(buf));
    CHECK_EQ_STR(buf, "10.10.99.0/24");
    CHECK(strstr(a->evidence, "\"covering_prefix\":\"10.10.0.0/16\"") != NULL);

    /* v6 flavor */
    cfg.n_watch = 2;
    vg_prefix_parse("2001:db8::/32", &cfg.watch_prefix[1]);
    cfg.watch_origin[1] = 64500;
    vg_engine_t *e6 = vg_engine_new(&cfg, rib, capture_alert, NULL);
    n_alerts = 0;
    feed(e6, announce("2001:db8:bad::/48", "1299 64666", "p2", 1299, 2000));
    CHECK_EQ_INT(count_type(VG_ALERT_SUBPREFIX), 1);
    vg_engine_free(e6);

    vg_engine_free(e);
    vg_rib_free(rib);
}

static void test_route_leak(void) {
    vg_config_t cfg;
    vg_config_defaults(&cfg);
    /* AS3356 and AS1299 are providers of AS64500 */
    cfg.n_rels = 2;
    cfg.rel_provider[0] = 3356; cfg.rel_customer[0] = 64500;
    cfg.rel_provider[1] = 1299; cfg.rel_customer[1] = 64500;
    /* AS6939 peers with AS64500 */
    cfg.n_peer_rels = 1;
    cfg.peer_a[0] = 6939; cfg.peer_b[0] = 64500;

    vg_rib_t *rib = vg_rib_new();
    vg_engine_t *e = vg_engine_new(&cfg, rib, capture_alert, NULL);
    n_alerts = 0;

    /* clean: customer route goes up to provider (valley-free) */
    feed(e, announce("203.0.113.0/24", "3356 64500 65001", "p1", 3356, 1000));
    /* clean: prepending doesn't confuse the classifier */
    feed(e, announce("203.0.113.0/24", "3356 64500 64500 65001", "p1", 3356, 1010));
    CHECK_EQ_INT(n_alerts, 0);

    /* leak: 64500 learns from provider 3356, re-exports to provider
     * 1299 (classic type-1 leak; path reads collector<-1299<-64500<-3356) */
    feed(e, announce("198.18.0.0/15", "1299 64500 3356 65002", "p2", 1299, 1100));
    CHECK_EQ_INT(count_type(VG_ALERT_LEAK), 1);
    const vg_alert_t *a = first_of(VG_ALERT_LEAK);
    CHECK_EQ_INT(a->observed_asn, 64500); /* the leaker */
    CHECK_EQ_INT(a->expected_asn, 1299);  /* leaked to */

    /* leak: provider route re-exported across a peering */
    n_alerts = 0;
    feed(e, announce("198.19.0.0/16", "6939 64500 3356 65003", "p3", 6939, 1200));
    CHECK_EQ_INT(count_type(VG_ALERT_LEAK), 1);
    CHECK_EQ_INT(first_of(VG_ALERT_LEAK)->observed_asn, 64500);

    /* unknown-relationship edges never alert */
    n_alerts = 0;
    feed(e, announce("198.20.0.0/16", "111 222 333 444", "p4", 111, 1300));
    CHECK_EQ_INT(n_alerts, 0);

    vg_engine_free(e);
    vg_rib_free(rib);
}

static void test_spike(void) {
    vg_config_t cfg;
    vg_config_defaults(&cfg);
    cfg.spike_window = 60;
    cfg.spike_factor = 10;
    cfg.spike_min = 20;

    vg_rib_t *rib = vg_rib_new();
    vg_engine_t *e = vg_engine_new(&cfg, rib, capture_alert, NULL);
    n_alerts = 0;

    /* steady trickle from many prefixes: no alerts (also keeps the
     * per-peer counter honest: spread across peers) */
    for (int i = 0; i < 15; i++) {
        char pfx[32], peer[16];
        snprintf(pfx, sizeof(pfx), "10.%d.0.0/16", i);
        snprintf(peer, sizeof(peer), "peer%d", i % 5);
        feed(e, announce(pfx, "1 2", peer, 1, i * 30.0));
    }
    CHECK_EQ_INT(n_alerts, 0);

    /* flap: one prefix bursts announce/withdraw pairs */
    double t = 1000;
    for (int i = 0; i < 15 && count_type(VG_ALERT_SPIKE) == 0; i++) {
        feed(e, announce("172.16.0.0/12", "1 2", "flappy", 1, t));
        feed(e, withdraw("172.16.0.0/12", "flappy", 1, t + 1));
        t += 2;
    }
    CHECK(count_type(VG_ALERT_SPIKE) >= 1);
    const vg_alert_t *a = first_of(VG_ALERT_SPIKE);
    CHECK(strstr(a->summary, "spike") != NULL);

    vg_engine_free(e);
    vg_rib_free(rib);
}

static void test_real_replay_no_false_positives(void) {
    if (access("data/fixtures/updates-sample.mrt", R_OK) != 0) {
        fprintf(stderr, "note: real fixture missing, skipping\n");
        return;
    }
    vg_config_t cfg;
    vg_config_defaults(&cfg);

    vg_rib_t *rib = vg_rib_new();
    vg_engine_t *e = vg_engine_new(&cfg, rib, capture_alert, NULL);
    n_alerts = 0;

    vg_mrt_stats_t mst;
    CHECK_EQ_INT(vg_mrt_replay("data/fixtures/updates-sample.mrt", 0,
                               vg_engine_sink, e, &mst), 0);
    vg_engine_stats_t st;
    vg_engine_stats(e, &st);
    CHECK_EQ_INT((int)st.events, (int)(mst.announces + mst.withdraws));
    /* no relationships and no watchlist configured -> hijack/subprefix/
     * leak must produce zero alerts on real clean traffic */
    CHECK_EQ_INT(count_type(VG_ALERT_HIJACK), 0);
    CHECK_EQ_INT(count_type(VG_ALERT_SUBPREFIX), 0);
    CHECK_EQ_INT(count_type(VG_ALERT_LEAK), 0);
    CHECK_EQ_INT(count_type(VG_ALERT_RPKI_INVALID), 0);

    vg_engine_free(e);
    vg_rib_free(rib);
}

int main(void) {
    test_origin_hijack_watchlist();
    test_learned_baseline();
    test_subprefix_hijack();
    test_route_leak();
    test_spike();
    test_real_replay_no_false_positives();
    TEST_MAIN_END();
}
