#include "../src/bgp/bgp.h"
#include "../src/ingest/mrtfile.h"
#include "../src/mrt/mrt.h"
#include "test.h"

#include <stdio.h>
#include <unistd.h>

/* ---- tiny MRT writer (tests only) -------------------------------- */

static void w8(FILE *f, uint8_t v) { fputc(v, f); }
static void w16(FILE *f, uint16_t v) { w8(f, (uint8_t)(v >> 8)); w8(f, (uint8_t)v); }
static void w32(FILE *f, uint32_t v) { w16(f, (uint16_t)(v >> 16)); w16(f, (uint16_t)v); }
static void wb(FILE *f, const uint8_t *p, size_t n) { fwrite(p, 1, n, f); }

static void mrt_header(FILE *f, uint32_t ts, uint16_t type, uint16_t subtype,
                       uint32_t len) {
    w32(f, ts);
    w16(f, type);
    w16(f, subtype);
    w32(f, len);
}

/* BGP4MP_MESSAGE_AS4 wrapping a full BGP message */
static void write_bgp4mp(FILE *f, uint32_t ts, uint32_t peer_as,
                         const uint8_t *msg, size_t msg_len) {
    uint32_t body = 4 + 4 + 2 + 2 + 4 + 4 + (uint32_t)msg_len;
    mrt_header(f, ts, VG_MRT_BGP4MP, VG_BGP4MP_MESSAGE_AS4, body);
    w32(f, peer_as);
    w32(f, 64999);        /* local AS */
    w16(f, 0);            /* ifindex */
    w16(f, 1);            /* AFI v4 */
    w8(f, 203); w8(f, 0); w8(f, 113); w8(f, 1);  /* peer ip */
    w8(f, 203); w8(f, 0); w8(f, 113); w8(f, 254);/* local ip */
    wb(f, msg, msg_len);
}

static size_t build_update(uint8_t *buf, size_t cap, const char *pfx,
                           const char *path_str) {
    static vg_bgp_update_t u;
    memset(&u, 0, sizeof(u));
    u.origin = VG_ORIGIN_IGP;
    u.has_path = true;
    vg_aspath_parse(path_str, &u.path);
    u.has_next_hop = true;
    u.next_hop[0] = 203; u.next_hop[2] = 113; u.next_hop[3] = 1;
    u.n_nlri = 1;
    vg_prefix_parse(pfx, &u.nlri[0]);
    int len = vg_bgp_write_update(&u, true, buf, cap);
    return len > 0 ? (size_t)len : 0;
}

static size_t build_withdraw(uint8_t *buf, size_t cap, const char *pfx) {
    static vg_bgp_update_t u;
    memset(&u, 0, sizeof(u));
    u.origin = VG_ORIGIN_UNSET;
    u.n_withdrawn = 1;
    vg_prefix_parse(pfx, &u.withdrawn[0]);
    int len = vg_bgp_write_update(&u, true, buf, cap);
    return len > 0 ? (size_t)len : 0;
}

/* TABLE_DUMP_V2: PEER_INDEX_TABLE with one AS4/v4 peer */
static void write_peer_index(FILE *f, uint32_t ts, uint32_t peer_as) {
    uint32_t body = 4 + 2 + 2 + (1 + 4 + 4 + 4);
    mrt_header(f, ts, VG_MRT_TABLE_DUMP_V2, VG_TDV2_PEER_INDEX_TABLE, body);
    w32(f, 0x0A000001); /* collector id */
    w16(f, 0);          /* view name len */
    w16(f, 1);          /* peer count */
    w8(f, 0x02);        /* flags: AS4, IPv4 */
    w32(f, 0x0A000002); /* peer BGP id */
    w8(f, 203); w8(f, 0); w8(f, 113); w8(f, 9);
    w32(f, peer_as);
}

/* One RIB_IPV4_UNICAST record with a single entry */
static void write_rib_entry(FILE *f, uint32_t ts, uint32_t seq,
                            const char *pfx, const char *path_str) {
    vg_prefix_t p;
    vg_prefix_parse(pfx, &p);
    uint8_t nlri[17];
    int nlri_len = vg_nlri_encode(&p, nlri, sizeof(nlri));

    vg_aspath_t path;
    vg_aspath_parse(path_str, &path);
    /* attrs: ORIGIN(4) + AS_PATH(3 + 2 + 4*count) + NEXT_HOP(7) */
    uint16_t alen = (uint16_t)(4 + 3 + 2 + 4 * path.count + 7);

    uint32_t body = 4 + (uint32_t)nlri_len + 2 + (2 + 4 + 2 + alen);
    mrt_header(f, ts, VG_MRT_TABLE_DUMP_V2, VG_TDV2_RIB_IPV4_UNICAST, body);
    w32(f, seq);
    wb(f, nlri, (size_t)nlri_len);
    w16(f, 1);        /* entry count */
    w16(f, 0);        /* peer index */
    w32(f, ts - 100); /* originated */
    w16(f, alen);
    /* ORIGIN IGP */
    w8(f, 0x40); w8(f, 1); w8(f, 1); w8(f, 0);
    /* AS_PATH, one AS_SEQUENCE, 4-byte ASNs (TABLE_DUMP_V2 rule) */
    w8(f, 0x40); w8(f, 2); w8(f, (uint8_t)(2 + 4 * path.count));
    w8(f, 2); w8(f, (uint8_t)path.count);
    for (int i = 0; i < path.count; i++) w32(f, path.as[i]);
    /* NEXT_HOP */
    w8(f, 0x40); w8(f, 3); w8(f, 4);
    w8(f, 203); w8(f, 0); w8(f, 113); w8(f, 9);
}

/* ---- event capture ------------------------------------------------ */

#define MAX_EV 64
static vg_event_t captured[MAX_EV];
static int n_captured;

static void capture(const vg_event_t *ev, void *user) {
    (void)user;
    if (n_captured < MAX_EV) captured[n_captured++] = *ev;
}

static void quiet(const vg_event_t *ev, void *user) {
    (void)ev;
    (void)user;
}

static const vg_event_t *find_event(const char *pfx, vg_event_kind_t kind) {
    vg_prefix_t p;
    vg_prefix_parse(pfx, &p);
    for (int i = 0; i < n_captured; i++)
        if (captured[i].kind == kind && vg_prefix_equal(&captured[i].prefix, &p))
            return &captured[i];
    return NULL;
}

int main(void) {
    /* ---- BGP4MP update stream ---- */
    char path[] = "/tmp/vigil_test_mrt_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    FILE *f = fdopen(fd, "wb");

    uint8_t msg[4096];
    size_t len;
    len = build_update(msg, sizeof(msg), "198.51.100.0/24", "6939 15169");
    write_bgp4mp(f, 1000, 6939, msg, len);
    len = build_update(msg, sizeof(msg), "203.0.113.0/24", "6939 3356 4200000001");
    write_bgp4mp(f, 1001, 6939, msg, len);
    len = build_withdraw(msg, sizeof(msg), "198.51.100.0/24");
    write_bgp4mp(f, 1002, 6939, msg, len);
    /* a KEEPALIVE should be counted as skipped, not an error */
    uint8_t ka[19];
    memset(ka, 0xFF, 16);
    ka[16] = 0; ka[17] = 19; ka[18] = VG_BGP_KEEPALIVE;
    write_bgp4mp(f, 1003, 6939, ka, sizeof(ka));
    fclose(f);

    n_captured = 0;
    vg_mrt_stats_t st;
    CHECK_EQ_INT(vg_mrt_replay(path, 0, capture, NULL, &st), 0);
    CHECK_EQ_INT((int)st.records, 4);
    CHECK_EQ_INT((int)st.bgp_updates, 3);
    CHECK_EQ_INT((int)st.announces, 2);
    CHECK_EQ_INT((int)st.withdraws, 1);
    CHECK_EQ_INT((int)st.unique_prefixes, 2);
    CHECK_EQ_INT((int)st.unique_origins, 2); /* 15169, 4200000001 */
    CHECK_EQ_INT((int)st.parse_errors, 0);
    CHECK_EQ_INT((int)st.skipped_records, 1);

    const vg_event_t *ev = find_event("198.51.100.0/24", VG_EV_ANNOUNCE);
    CHECK(ev != NULL);
    if (ev) {
        CHECK_EQ_INT(vg_event_origin(ev), 15169);
        CHECK_EQ_STR(ev->peer, "203.0.113.1");
        CHECK_EQ_INT(ev->peer_asn, 6939);
        CHECK_EQ_STR(ev->source, "mrt");
        CHECK(ev->timestamp == 1000.0);
    }
    ev = find_event("203.0.113.0/24", VG_EV_ANNOUNCE);
    CHECK(ev != NULL);
    if (ev) CHECK_EQ_INT(vg_event_origin(ev), 4200000001u);
    CHECK(find_event("198.51.100.0/24", VG_EV_WITHDRAW) != NULL);
    unlink(path);

    /* ---- TABLE_DUMP_V2 snapshot ---- */
    char path2[] = "/tmp/vigil_test_mrt2_XXXXXX";
    fd = mkstemp(path2);
    CHECK(fd >= 0);
    f = fdopen(fd, "wb");
    write_peer_index(f, 2000, 6939);
    write_rib_entry(f, 2000, 0, "8.8.8.0/24", "6939 15169");
    write_rib_entry(f, 2000, 1, "1.1.1.0/24", "6939 13335");
    fclose(f);

    n_captured = 0;
    CHECK_EQ_INT(vg_mrt_replay(path2, 0, capture, NULL, &st), 0);
    CHECK_EQ_INT((int)st.records, 3);
    CHECK_EQ_INT((int)st.rib_entries, 2);
    CHECK_EQ_INT((int)st.announces, 2);
    CHECK_EQ_INT((int)st.unique_prefixes, 2);
    CHECK_EQ_INT((int)st.unique_origins, 2);
    CHECK_EQ_INT((int)st.parse_errors, 0);

    ev = find_event("8.8.8.0/24", VG_EV_ANNOUNCE);
    CHECK(ev != NULL);
    if (ev) {
        CHECK_EQ_INT(vg_event_origin(ev), 15169);
        CHECK_EQ_INT(ev->peer_asn, 6939);
        CHECK_EQ_STR(ev->peer, "203.0.113.9");
    }
    ev = find_event("1.1.1.0/24", VG_EV_ANNOUNCE);
    CHECK(ev != NULL);
    if (ev) CHECK_EQ_INT(vg_event_origin(ev), 13335);
    unlink(path2);

    /* ---- corrupt file: truncated record body ---- */
    char path3[] = "/tmp/vigil_test_mrt3_XXXXXX";
    fd = mkstemp(path3);
    CHECK(fd >= 0);
    f = fdopen(fd, "wb");
    mrt_header(f, 3000, VG_MRT_BGP4MP, VG_BGP4MP_MESSAGE_AS4, 100);
    w32(f, 6939); /* only 4 of the promised 100 bytes */
    fclose(f);
    n_captured = 0;
    CHECK_EQ_INT(vg_mrt_replay(path3, 0, capture, NULL, &st), -1);
    unlink(path3);

    /* ---- absurd record length is rejected ---- */
    char path4[] = "/tmp/vigil_test_mrt4_XXXXXX";
    fd = mkstemp(path4);
    CHECK(fd >= 0);
    f = fdopen(fd, "wb");
    mrt_header(f, 3000, VG_MRT_BGP4MP, VG_BGP4MP_MESSAGE_AS4, 0x7FFFFFFF);
    fclose(f);
    CHECK_EQ_INT(vg_mrt_replay(path4, 0, capture, NULL, &st), -1);
    unlink(path4);

    /* ---- real-world fixture (carved from a RIPE RIS rrc00 dump,
     * counts cross-validated against mrtparse — see tools/crosscheck.py) */
    if (access("data/fixtures/updates-sample.mrt", R_OK) == 0) {
        vg_mrt_stats_t rst;
        CHECK_EQ_INT(vg_mrt_replay("data/fixtures/updates-sample.mrt", 0,
                                   quiet, NULL, &rst), 0);
        CHECK_EQ_INT((int)rst.records, 400);
        CHECK_EQ_INT((int)rst.bgp_updates, 396);
        CHECK_EQ_INT((int)rst.announces, 516);
        CHECK_EQ_INT((int)rst.withdraws, 44);
        CHECK_EQ_INT((int)rst.unique_prefixes, 160);
        CHECK_EQ_INT((int)rst.unique_origins, 84);
        CHECK_EQ_INT((int)rst.parse_errors, 0);
    } else {
        fprintf(stderr, "note: real-world fixture not found, skipping\n");
    }

    TEST_MAIN_END();
}
