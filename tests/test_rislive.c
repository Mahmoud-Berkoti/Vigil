#include "../src/ingest/rislive.h"
#include "test.h"

#include <stdlib.h>
#include <unistd.h>

#define MAX_EV 32
static vg_event_t captured[MAX_EV];
static int n_captured;
static void capture(const vg_event_t *ev, void *user) {
    (void)user;
    if (n_captured < MAX_EV) captured[n_captured++] = *ev;
}

/* A realistic RIS Live UPDATE line (schema per ris-live.ripe.net docs) */
static const char *SAMPLE =
    "{\"type\":\"ris_message\",\"data\":{\"timestamp\":1751846400.51,"
    "\"peer\":\"203.0.113.1\",\"peer_asn\":\"6939\",\"id\":\"x\","
    "\"host\":\"rrc00.ripe.net\",\"type\":\"UPDATE\","
    "\"path\":[6939,1299,[64500,64501]],\"community\":[[6939,100],[1299,20]],"
    "\"origin\":\"igp\",\"med\":50,"
    "\"announcements\":[{\"next_hop\":\"203.0.113.1\","
    "\"prefixes\":[\"198.51.100.0/24\",\"2001:db8::/32\"]}],"
    "\"withdrawals\":[\"192.0.2.0/24\"]}}";

int main(void) {
    n_captured = 0;
    int rc = vg_rislive_handle_line(SAMPLE, strlen(SAMPLE), capture, NULL);
    CHECK_EQ_INT(rc, 3);
    CHECK_EQ_INT(n_captured, 3);

    /* withdrawal first */
    CHECK_EQ_INT((int)captured[0].kind, (int)VG_EV_WITHDRAW);
    char buf[VG_PREFIX_STRLEN];
    vg_prefix_format(&captured[0].prefix, buf, sizeof(buf));
    CHECK_EQ_STR(buf, "192.0.2.0/24");
    CHECK_EQ_INT(captured[0].peer_asn, 6939);
    CHECK_EQ_STR(captured[0].peer, "203.0.113.1");
    CHECK_EQ_STR(captured[0].source, "rislive");

    /* v4 announce */
    CHECK_EQ_INT((int)captured[1].kind, (int)VG_EV_ANNOUNCE);
    vg_prefix_format(&captured[1].prefix, buf, sizeof(buf));
    CHECK_EQ_STR(buf, "198.51.100.0/24");
    CHECK_EQ_INT(captured[1].path.count, 4); /* AS_SET flattened */
    CHECK_EQ_INT(captured[1].path.as[0], 6939);
    CHECK(captured[1].path.origin_from_set);
    CHECK_EQ_INT((int)captured[1].origin_attr, (int)VG_ORIGIN_IGP);
    CHECK(captured[1].has_med && captured[1].med == 50);
    CHECK_EQ_INT(captured[1].n_communities, 2);
    CHECK_EQ_INT(captured[1].communities[0], (6939u << 16) | 100);
    CHECK_EQ_INT((int)captured[1].next_hop_family, VG_AF_INET);
    CHECK(captured[1].timestamp > 1751846400.0);

    /* v6 announce shares attributes */
    vg_prefix_format(&captured[2].prefix, buf, sizeof(buf));
    CHECK_EQ_STR(buf, "2001:db8::/32");

    /* non-UPDATE ris messages are ignored, not errors */
    const char *keepalive =
        "{\"type\":\"ris_message\",\"data\":{\"type\":\"KEEPALIVE\","
        "\"peer\":\"x\",\"peer_asn\":\"1\",\"timestamp\":1}}";
    n_captured = 0;
    CHECK_EQ_INT(vg_rislive_handle_line(keepalive, strlen(keepalive),
                                        capture, NULL), 0);
    CHECK_EQ_INT(n_captured, 0);

    /* garbage line is a parse error */
    CHECK_EQ_INT(vg_rislive_handle_line("not json", 8, capture, NULL), -1);

    /* bad prefixes inside a valid message are skipped, good ones kept */
    const char *mixed =
        "{\"type\":\"ris_message\",\"data\":{\"type\":\"UPDATE\","
        "\"timestamp\":1,\"peer\":\"p\",\"peer_asn\":\"2\",\"path\":[2,3],"
        "\"origin\":\"igp\",\"announcements\":[{\"next_hop\":\"10.0.0.1\","
        "\"prefixes\":[\"999.0.0.0/8\",\"10.0.0.0/8\"]}]}}";
    n_captured = 0;
    CHECK_EQ_INT(vg_rislive_handle_line(mixed, strlen(mixed), capture, NULL), 1);
    vg_prefix_format(&captured[0].prefix, buf, sizeof(buf));
    CHECK_EQ_STR(buf, "10.0.0.0/8");

    /* ---- opt-in live smoke test (needs network egress) ----
     * VIGIL_LIVE_TEST=1 make test */
    if (getenv("VIGIL_LIVE_TEST")) {
        vg_rislive_opts_t opts;
        memset(&opts, 0, sizeof(opts));
        n_captured = 0;
        vg_rislive_t *c = vg_rislive_start(&opts, capture, NULL);
        CHECK(c != NULL);
        int waited = 0;
        vg_rislive_stats_t st;
        memset(&st, 0, sizeof(st));
        while (waited < 30) {
            sleep(1);
            waited++;
            vg_rislive_stats(c, &st);
            if (st.events > 100) break;
        }
        fprintf(stderr,
                "live: messages=%llu events=%llu errors=%llu in %ds\n",
                (unsigned long long)st.messages, (unsigned long long)st.events,
                (unsigned long long)st.parse_errors, waited);
        CHECK(st.messages > 0);
        CHECK(st.events > 0);
        vg_rislive_stop(c);
    } else {
        fprintf(stderr, "note: live smoke test skipped (set VIGIL_LIVE_TEST=1)\n");
    }

    TEST_MAIN_END();
}
