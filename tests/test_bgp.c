#include "../src/bgp/bgp.h"
#include "test.h"

/* ------------------------------------------------------------------ */
/* Hand-verified wire fixture: a classic IPv4 announce                 */
/*   ORIGIN=IGP, AS_PATH=6939 15169 (2-octet), NEXT_HOP=192.0.2.1,     */
/*   NLRI=198.51.100.0/24                                              */
/* ------------------------------------------------------------------ */
static const uint8_t FIX_ANNOUNCE[] = {
    /* marker */
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x00,0x2F,       /* length = 47 */
    0x02,            /* type = UPDATE */
    0x00,0x00,       /* withdrawn routes length = 0 */
    0x00,0x14,       /* total path attribute length = 20 */
    /* ORIGIN: flags 0x40 (well-known transitive), type 1, len 1, IGP */
    0x40,0x01,0x01,0x00,
    /* AS_PATH: flags 0x40, type 2, len 6: AS_SEQUENCE of 2: 6939 15169 */
    0x40,0x02,0x06,0x02,0x02,0x1B,0x1B,0x3B,0x41,
    /* NEXT_HOP: flags 0x40, type 3, len 4: 192.0.2.1 */
    0x40,0x03,0x04,0xC0,0x00,0x02,0x01,
    /* NLRI: 198.51.100.0/24 */
    0x18,0xC6,0x33,0x64,
};

/* Withdraw-only UPDATE: withdraw 10.1.0.0/16 and 10.2.3.0/24 */
static const uint8_t FIX_WITHDRAW[] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x00,0x1E,       /* length = 30 */
    0x02,
    0x00,0x07,       /* withdrawn length = 7 */
    0x10,0x0A,0x01,  /* 10.1.0.0/16 */
    0x18,0x0A,0x02,0x03, /* 10.2.3.0/24 */
    0x00,0x00,       /* no attributes */
};

static void expect_prefix(const vg_prefix_t *p, const char *want) {
    char buf[VG_PREFIX_STRLEN];
    CHECK(vg_prefix_format(p, buf, sizeof(buf)) > 0);
    CHECK_EQ_STR(buf, want);
}

static void test_fixture_announce(void) {
    vg_bgp_hdr_t hdr;
    CHECK_EQ_INT(vg_bgp_parse_header(FIX_ANNOUNCE, sizeof(FIX_ANNOUNCE), &hdr), 0);
    CHECK_EQ_INT(hdr.type, VG_BGP_UPDATE);
    CHECK_EQ_INT(hdr.len, sizeof(FIX_ANNOUNCE));

    static vg_bgp_update_t u;
    CHECK_EQ_INT(vg_bgp_parse_update(FIX_ANNOUNCE + VG_BGP_HEADER_LEN,
                                     sizeof(FIX_ANNOUNCE) - VG_BGP_HEADER_LEN,
                                     false, &u), 0);
    CHECK_EQ_INT(u.n_withdrawn, 0);
    CHECK_EQ_INT(u.n_nlri, 1);
    expect_prefix(&u.nlri[0], "198.51.100.0/24");
    CHECK_EQ_INT(u.origin, VG_ORIGIN_IGP);
    CHECK(u.has_path);
    CHECK_EQ_INT(u.path.count, 2);
    CHECK_EQ_INT(u.path.as[0], 6939);
    CHECK_EQ_INT(u.path.as[1], 15169);
    CHECK_EQ_INT(vg_aspath_origin(&u.path), 15169);
    CHECK(u.has_next_hop);
    CHECK_EQ_INT(u.next_hop[0], 192);
    CHECK_EQ_INT(u.next_hop[3], 1);
}

static void test_fixture_withdraw(void) {
    vg_bgp_hdr_t hdr;
    CHECK_EQ_INT(vg_bgp_parse_header(FIX_WITHDRAW, sizeof(FIX_WITHDRAW), &hdr), 0);
    static vg_bgp_update_t u;
    CHECK_EQ_INT(vg_bgp_parse_update(FIX_WITHDRAW + VG_BGP_HEADER_LEN,
                                     sizeof(FIX_WITHDRAW) - VG_BGP_HEADER_LEN,
                                     false, &u), 0);
    CHECK_EQ_INT(u.n_withdrawn, 2);
    expect_prefix(&u.withdrawn[0], "10.1.0.0/16");
    expect_prefix(&u.withdrawn[1], "10.2.3.0/24");
    CHECK_EQ_INT(u.n_nlri, 0);
}

static void test_header_errors(void) {
    uint8_t buf[sizeof(FIX_ANNOUNCE)];
    memcpy(buf, FIX_ANNOUNCE, sizeof(buf));
    vg_bgp_hdr_t hdr;

    /* truncated */
    CHECK_EQ_INT(vg_bgp_parse_header(buf, 10, &hdr), VG_BGP_ETRUNC);

    /* bad marker */
    buf[3] = 0x00;
    CHECK_EQ_INT(vg_bgp_parse_header(buf, sizeof(buf), &hdr), VG_BGP_EBADMARKER);
    buf[3] = 0xFF;

    /* bad type */
    buf[18] = 9;
    CHECK_EQ_INT(vg_bgp_parse_header(buf, sizeof(buf), &hdr), VG_BGP_EBADTYPE);
    buf[18] = 2;

    /* length below minimum for UPDATE */
    buf[16] = 0; buf[17] = 20;
    CHECK_EQ_INT(vg_bgp_parse_header(buf, sizeof(buf), &hdr), VG_BGP_EBADLEN);

    /* length > 4096 */
    buf[16] = 0x10; buf[17] = 0x01;
    CHECK_EQ_INT(vg_bgp_parse_header(buf, sizeof(buf), &hdr), VG_BGP_EBADLEN);

    /* KEEPALIVE must be exactly 19 */
    uint8_t ka[19];
    memset(ka, 0xFF, 16);
    ka[16] = 0; ka[17] = 19; ka[18] = VG_BGP_KEEPALIVE;
    CHECK_EQ_INT(vg_bgp_parse_header(ka, sizeof(ka), &hdr), 0);
    ka[17] = 20;
    CHECK_EQ_INT(vg_bgp_parse_header(ka, sizeof(ka), &hdr), VG_BGP_EBADLEN);
}

static void test_malformed_updates(void) {
    static vg_bgp_update_t u;
    uint8_t buf[128];

    /* withdrawn length overruns message */
    uint8_t m1[] = {0x00, 0x40, 0x00, 0x00};
    CHECK_EQ_INT(vg_bgp_parse_update(m1, sizeof(m1), false, &u), VG_BGP_EBADLEN);

    /* attribute length overruns attribute section */
    uint8_t m2[] = {0x00,0x00, 0x00,0x04, 0x40,0x01,0x05,0x00};
    CHECK_EQ_INT(vg_bgp_parse_update(m2, sizeof(m2), false, &u), VG_BGP_EATTRLEN);

    /* truncated attribute header */
    uint8_t m3[] = {0x00,0x00, 0x00,0x01, 0x40};
    CHECK_EQ_INT(vg_bgp_parse_update(m3, sizeof(m3), false, &u), VG_BGP_ETRUNC);

    /* NLRI prefix length 33 for v4 */
    uint8_t m4[] = {0x00,0x03, 0x21,0x0A,0x00, 0x00,0x00};
    CHECK_EQ_INT(vg_bgp_parse_update(m4, sizeof(m4), false, &u), VG_BGP_EPREFIXLEN);

    /* ORIGIN with wrong length */
    uint8_t m5[] = {0x00,0x00, 0x00,0x05, 0x40,0x01,0x02,0x00,0x00};
    CHECK_EQ_INT(vg_bgp_parse_update(m5, sizeof(m5), false, &u), VG_BGP_EATTRLEN);

    /* ORIGIN with invalid value 3 */
    uint8_t m5b[] = {0x00,0x00, 0x00,0x04, 0x40,0x01,0x01,0x03};
    CHECK_EQ_INT(vg_bgp_parse_update(m5b, sizeof(m5b), false, &u), VG_BGP_EATTRLEN);

    /* AS_PATH with invalid segment type */
    uint8_t m6[] = {0x00,0x00, 0x00,0x07, 0x40,0x02,0x04, 0x05,0x01,0x1B,0x1B};
    CHECK_EQ_INT(vg_bgp_parse_update(m6, sizeof(m6), false, &u), VG_BGP_ESEGTYPE);

    /* AS_PATH segment claiming more ASNs than remain */
    uint8_t m7[] = {0x00,0x00, 0x00,0x07, 0x40,0x02,0x04, 0x02,0x05,0x1B,0x1B};
    CHECK_EQ_INT(vg_bgp_parse_update(m7, sizeof(m7), false, &u), VG_BGP_ETRUNC);

    /* unknown well-known (non-optional) attribute is a protocol error */
    uint8_t m8[] = {0x00,0x00, 0x00,0x04, 0x40,0x63,0x01,0x00};
    CHECK_EQ_INT(vg_bgp_parse_update(m8, sizeof(m8), false, &u), VG_BGP_EATTRLEN);

    /* unknown OPTIONAL attribute is skipped */
    uint8_t m9[] = {0x00,0x00, 0x00,0x04, 0xC0,0x63,0x01,0x00};
    CHECK_EQ_INT(vg_bgp_parse_update(m9, sizeof(m9), false, &u), 0);
    CHECK_EQ_INT(u.n_unknown_attrs, 1);

    /* announce missing mandatory NEXT_HOP */
    uint8_t m10[] = {0x00,0x00, 0x00,0x0D,
                     0x40,0x01,0x01,0x00,
                     0x40,0x02,0x06,0x02,0x02,0x1B,0x1B,0x3B,0x41,
                     0x18,0xC6,0x33,0x64};
    CHECK_EQ_INT(vg_bgp_parse_update(m10, sizeof(m10), false, &u), VG_BGP_EMISSING);

    /* MP_REACH with unsupported AFI */
    uint8_t m11[] = {0x00,0x00, 0x00,0x08, 0x80,0x0E,0x05, 0x00,0x19,0x01,0x00,0x00};
    CHECK_EQ_INT(vg_bgp_parse_update(m11, sizeof(m11), false, &u), VG_BGP_EAFI);

    /* empty update (End-of-RIB marker) is valid */
    uint8_t m12[] = {0x00,0x00, 0x00,0x00};
    CHECK_EQ_INT(vg_bgp_parse_update(m12, sizeof(m12), false, &u), 0);
    CHECK_EQ_INT(u.n_nlri, 0);
    CHECK_EQ_INT(u.n_withdrawn, 0);

    (void)buf;
}

static void test_4byte_asn_roundtrip(void) {
    static vg_bgp_update_t u, v;
    memset(&u, 0, sizeof(u));
    u.origin = VG_ORIGIN_IGP;
    u.has_path = true;
    vg_aspath_parse("4200000001 6939 15169", &u.path);
    u.has_next_hop = true;
    u.next_hop[0] = 192; u.next_hop[1] = 0; u.next_hop[2] = 2; u.next_hop[3] = 1;
    u.n_nlri = 1;
    vg_prefix_parse("203.0.113.0/24", &u.nlri[0]);
    u.has_med = true; u.med = 100;
    u.n_communities = 2;
    u.communities[0] = (6939u << 16) | 100;
    u.communities[1] = (15169u << 16) | 200;

    uint8_t buf[4096];
    int len = vg_bgp_write_update(&u, true, buf, sizeof(buf));
    CHECK(len > 0);

    vg_bgp_hdr_t hdr;
    CHECK_EQ_INT(vg_bgp_parse_header(buf, (size_t)len, &hdr), 0);
    CHECK_EQ_INT(hdr.len, len);
    CHECK_EQ_INT(vg_bgp_parse_update(buf + VG_BGP_HEADER_LEN,
                                     (size_t)len - VG_BGP_HEADER_LEN, true, &v), 0);
    CHECK_EQ_INT(v.path.count, 3);
    CHECK_EQ_INT(v.path.as[0], 4200000001u);
    CHECK_EQ_INT(vg_aspath_origin(&v.path), 15169);
    CHECK(v.has_med && v.med == 100);
    CHECK_EQ_INT(v.n_communities, 2);
    CHECK_EQ_INT(v.communities[1], (15169u << 16) | 200);
    expect_prefix(&v.nlri[0], "203.0.113.0/24");

    /* the same path through a 2-octet session must truncate ASNs —
     * parse back with as4=false must NOT yield 4200000001 */
    len = vg_bgp_write_update(&u, false, buf, sizeof(buf));
    CHECK(len > 0);
    CHECK_EQ_INT(vg_bgp_parse_update(buf + VG_BGP_HEADER_LEN,
                                     (size_t)len - VG_BGP_HEADER_LEN, false, &v), 0);
    CHECK(v.path.as[0] != 4200000001u);
}

static void test_ipv6_mp_reach_roundtrip(void) {
    static vg_bgp_update_t u, v;
    memset(&u, 0, sizeof(u));
    u.origin = VG_ORIGIN_IGP;
    u.has_path = true;
    vg_aspath_parse("6939 3320", &u.path);
    u.has_mp_reach = true;
    u.mp_af = VG_AF_INET6;
    u.mp_next_hop_len = 16;
    u.mp_next_hop[0] = 0x20; u.mp_next_hop[1] = 0x01; u.mp_next_hop[2] = 0x0d;
    u.mp_next_hop[3] = 0xb8; u.mp_next_hop[15] = 0x01;
    u.n_mp_nlri = 2;
    vg_prefix_parse("2001:db8::/32", &u.mp_nlri[0]);
    vg_prefix_parse("2001:db8:cafe::/48", &u.mp_nlri[1]);

    uint8_t buf[4096];
    int len = vg_bgp_write_update(&u, true, buf, sizeof(buf));
    CHECK(len > 0);
    CHECK_EQ_INT(vg_bgp_parse_update(buf + VG_BGP_HEADER_LEN,
                                     (size_t)len - VG_BGP_HEADER_LEN, true, &v), 0);
    CHECK(v.has_mp_reach);
    CHECK_EQ_INT(v.mp_af, VG_AF_INET6);
    CHECK_EQ_INT(v.n_mp_nlri, 2);
    expect_prefix(&v.mp_nlri[0], "2001:db8::/32");
    expect_prefix(&v.mp_nlri[1], "2001:db8:cafe::/48");
    CHECK_EQ_INT(v.mp_next_hop_len, 16);
    CHECK_EQ_INT(v.mp_next_hop[15], 0x01);

    /* MP_UNREACH round trip */
    memset(&u, 0, sizeof(u));
    u.origin = VG_ORIGIN_UNSET;
    u.has_mp_unreach = true;
    u.mp_unreach_af = VG_AF_INET6;
    u.n_mp_unreach = 1;
    vg_prefix_parse("2001:db8::/32", &u.mp_unreach[0]);
    len = vg_bgp_write_update(&u, true, buf, sizeof(buf));
    CHECK(len > 0);
    CHECK_EQ_INT(vg_bgp_parse_update(buf + VG_BGP_HEADER_LEN,
                                     (size_t)len - VG_BGP_HEADER_LEN, true, &v), 0);
    CHECK(v.has_mp_unreach);
    CHECK_EQ_INT(v.n_mp_unreach, 1);
    expect_prefix(&v.mp_unreach[0], "2001:db8::/32");
}

static void test_as4_path_merge(void) {
    /* A 2-octet session where AS_PATH contains AS_TRANS (23456) and
     * AS4_PATH carries the real 4-octet path (RFC 6793). */
    uint8_t msg[] = {
        0x00,0x00,       /* no withdrawn */
        0x00,0x1D,       /* attr len = 29 */
        0x40,0x01,0x01,0x00,                       /* ORIGIN IGP */
        /* AS_PATH (2-octet): 6939 23456 */
        0x40,0x02,0x06, 0x02,0x02, 0x1B,0x1B, 0x5B,0xA0,
        /* AS4_PATH (always 4-octet): 4200000001 */
        0xC0,0x11,0x06, 0x02,0x01, 0xFA,0x56,0xEA,0x01,
        0x40,0x03,0x04, 0xC0,0x00,0x02,0x01,       /* NEXT_HOP */
        0x18,0xC6,0x33,0x64,                       /* 198.51.100.0/24 */
    };
    static vg_bgp_update_t u;
    CHECK_EQ_INT(vg_bgp_parse_update(msg, sizeof(msg), false, &u), 0);
    CHECK_EQ_INT(u.path.count, 2);
    CHECK_EQ_INT(u.path.as[0], 6939);
    CHECK_EQ_INT(u.path.as[1], 4200000001u); /* AS_TRANS replaced */
    CHECK_EQ_INT(vg_aspath_origin(&u.path), 4200000001u);
}

static void test_open_parse(void) {
    /* OPEN payload: version 4, AS 23456, hold 90, id 10.0.0.1, opt
     * params: capabilities MP v4, MP v6, 4-octet AS 4200000001 */
    uint8_t open[] = {
        0x04,             /* version */
        0x5B,0xA0,        /* my AS = 23456 (AS_TRANS) */
        0x00,0x5A,        /* hold = 90 */
        0x0A,0x00,0x00,0x01,
        0x18,             /* opt param len = 24 */
        0x02,0x06, 0x01,0x04, 0x00,0x01,0x00,0x01,   /* cap: MP v4/unicast */
        0x02,0x06, 0x01,0x04, 0x00,0x02,0x00,0x01,   /* cap: MP v6/unicast */
        0x02,0x06, 0x41,0x04, 0xFA,0x56,0xEA,0x01,   /* cap: AS4 */
    };
    vg_bgp_open_t o;
    CHECK_EQ_INT(vg_bgp_parse_open(open, sizeof(open), &o), 0);
    CHECK_EQ_INT(o.version, 4);
    CHECK_EQ_INT(o.my_as, 23456);
    CHECK_EQ_INT(o.hold_time, 90);
    CHECK(o.cap_mp_ipv4);
    CHECK(o.cap_mp_ipv6);
    CHECK(o.cap_as4);
    CHECK_EQ_INT(o.as4, 4200000001u);

    /* truncated opt params */
    open[9] = 0x30;
    CHECK(vg_bgp_parse_open(open, sizeof(open), &o) != 0);
}

/* Quick deterministic mini-fuzz (full run: `make fuzz` with ASan). */
static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void test_mini_fuzz(void) {
    static vg_bgp_update_t u;
    uint8_t buf[512];

    /* pure random buffers */
    for (int iter = 0; iter < 20000; iter++) {
        size_t len = rnd() % sizeof(buf);
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)rnd();
        vg_bgp_hdr_t hdr;
        vg_bgp_parse_header(buf, len, &hdr);
        vg_bgp_parse_update(buf, len, (iter & 1) != 0, &u);
        vg_bgp_open_t o;
        vg_bgp_parse_open(buf, len, &o);
    }

    /* mutations of a valid message */
    for (int iter = 0; iter < 20000; iter++) {
        uint8_t msg[sizeof(FIX_ANNOUNCE)];
        memcpy(msg, FIX_ANNOUNCE, sizeof(msg));
        int nmut = 1 + (int)(rnd() % 4);
        for (int i = 0; i < nmut; i++)
            msg[rnd() % sizeof(msg)] = (uint8_t)rnd();
        vg_bgp_hdr_t hdr;
        if (vg_bgp_parse_header(msg, sizeof(msg), &hdr) == 0)
            vg_bgp_parse_update(msg + VG_BGP_HEADER_LEN,
                                sizeof(msg) - VG_BGP_HEADER_LEN, false, &u);
    }
    CHECK(1); /* reached without crashing */
}

int main(void) {
    test_fixture_announce();
    test_fixture_withdraw();
    test_header_errors();
    test_malformed_updates();
    test_4byte_asn_roundtrip();
    test_ipv6_mp_reach_roundtrip();
    test_as4_path_merge();
    test_open_parse();
    test_mini_fuzz();
    TEST_MAIN_END();
}
