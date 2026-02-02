/* Fuzz driver for the BGP wire parsers. Built with ASan/UBSan by
 * `make fuzz`. Deterministic (seeded xorshift) so failures reproduce;
 * override iterations with FUZZ_ITERS, seed with FUZZ_SEED. */
#include "../src/bgp/bgp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t rng_state;
static uint64_t rnd(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

/* seed corpus: valid messages produced by our own serializer */
static int build_seed(uint8_t *buf, size_t n, int variant) {
    static vg_bgp_update_t u;
    memset(&u, 0, sizeof(u));
    u.origin = VG_ORIGIN_IGP;
    u.has_path = true;
    vg_aspath_parse("6939 1299 3356 15169", &u.path);

    switch (variant % 3) {
    case 0:
        u.has_next_hop = true;
        u.next_hop[0] = 192; u.next_hop[2] = 2; u.next_hop[3] = 1;
        u.n_nlri = 3;
        vg_prefix_parse("198.51.100.0/24", &u.nlri[0]);
        vg_prefix_parse("203.0.113.0/24", &u.nlri[1]);
        vg_prefix_parse("192.0.2.0/25", &u.nlri[2]);
        u.n_communities = 3;
        u.communities[0] = 0x1B1B0064;
        break;
    case 1:
        u.has_mp_reach = true;
        u.mp_af = VG_AF_INET6;
        u.mp_next_hop_len = 16;
        u.mp_next_hop[0] = 0x20; u.mp_next_hop[1] = 0x01;
        u.n_mp_nlri = 2;
        vg_prefix_parse("2001:db8::/32", &u.mp_nlri[0]);
        vg_prefix_parse("2001:db8:1::/48", &u.mp_nlri[1]);
        break;
    default:
        u.origin = VG_ORIGIN_UNSET;
        u.has_path = false;
        u.n_withdrawn = 2;
        vg_prefix_parse("10.0.0.0/8", &u.withdrawn[0]);
        vg_prefix_parse("172.16.0.0/12", &u.withdrawn[1]);
        break;
    }
    return vg_bgp_write_update(&u, variant % 2 == 0, buf, n);
}

int main(void) {
    long iters = 500000;
    const char *e = getenv("FUZZ_ITERS");
    if (e) iters = atol(e);
    rng_state = 0x9E3779B97F4A7C15ULL;
    e = getenv("FUZZ_SEED");
    if (e) rng_state = (uint64_t)strtoull(e, NULL, 0);

    static vg_bgp_update_t u;
    uint8_t buf[VG_BGP_MAX_LEN + 64];

    for (long iter = 0; iter < iters; iter++) {
        size_t len;
        if (iter % 3 == 0) {
            /* pure random garbage, random length */
            len = rnd() % sizeof(buf);
            for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)rnd();
        } else {
            /* valid seed message with random byte/bit mutations */
            int slen = build_seed(buf, sizeof(buf), (int)(rnd() % 3));
            if (slen <= 0) { fprintf(stderr, "seed build failed\n"); return 1; }
            len = (size_t)slen;
            int nmut = (int)(rnd() % 8);
            for (int i = 0; i < nmut; i++) {
                size_t pos = rnd() % len;
                if (rnd() & 1) buf[pos] = (uint8_t)rnd();
                else buf[pos] ^= (uint8_t)(1u << (rnd() % 8));
            }
            /* occasionally truncate */
            if (rnd() % 4 == 0) len = rnd() % (len + 1);
        }

        vg_bgp_hdr_t hdr;
        bool as4 = (rnd() & 1) != 0;
        if (vg_bgp_parse_header(buf, len, &hdr) == 0 &&
            hdr.type == VG_BGP_UPDATE) {
            vg_bgp_parse_update(buf + VG_BGP_HEADER_LEN,
                                (size_t)hdr.len - VG_BGP_HEADER_LEN, as4, &u);
        }
        vg_bgp_parse_update(buf, len, as4, &u);
        vg_bgp_open_t o;
        vg_bgp_parse_open(buf, len, &o);
    }

    printf("fuzz ok: %ld iterations, no crashes\n", iters);
    return 0;
}
