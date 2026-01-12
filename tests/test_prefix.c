#include "../src/vigil.h"
#include "test.h"

/* Table-driven prefix parse/format tests, v4 + v6, incl. /0, /32, /128
 * and malformed inputs. */

struct ok_case {
    const char *in;
    const char *want; /* canonical formatting */
    int family;
    int len;
};

static const struct ok_case ok_cases[] = {
    {"10.0.0.0/8", "10.0.0.0/8", VG_AF_INET, 8},
    {"0.0.0.0/0", "0.0.0.0/0", VG_AF_INET, 0},
    {"255.255.255.255/32", "255.255.255.255/32", VG_AF_INET, 32},
    {"192.0.2.1/32", "192.0.2.1/32", VG_AF_INET, 32},
    /* host bits beyond the mask are normalized away */
    {"10.1.2.3/8", "10.0.0.0/8", VG_AF_INET, 8},
    {"192.0.2.255/25", "192.0.2.128/25", VG_AF_INET, 25},
    {"1.2.3.4/0", "0.0.0.0/0", VG_AF_INET, 0},
    {"2001:db8::/32", "2001:db8::/32", VG_AF_INET6, 32},
    {"::/0", "::/0", VG_AF_INET6, 0},
    {"2001:db8::1/128", "2001:db8::1/128", VG_AF_INET6, 128},
    {"2001:db8:ffff::/33", "2001:db8:8000::/33", VG_AF_INET6, 33},
    {"::ffff:1.2.3.4/128", "::ffff:1.2.3.4/128", VG_AF_INET6, 128},
};

static const char *bad_cases[] = {
    "",
    "10.0.0.0",        /* no length */
    "10.0.0.0/",       /* empty length */
    "10.0.0.0/33",     /* v4 length out of range */
    "10.0.0.0/-1",
    "10.0.0.0/8x",
    "10.0.0/8",        /* truncated address */
    "300.0.0.0/8",
    "2001:db8::/129",  /* v6 length out of range */
    "2001:zz8::/32",
    "/24",
    "10.0.0.0/ 8",
};

int main(void) {
    for (size_t i = 0; i < sizeof(ok_cases) / sizeof(ok_cases[0]); i++) {
        const struct ok_case *c = &ok_cases[i];
        vg_prefix_t p;
        int rc = vg_prefix_parse(c->in, &p);
        CHECK_EQ_INT(rc, 0);
        if (rc != 0) continue;
        CHECK_EQ_INT(p.family, c->family);
        CHECK_EQ_INT(p.len, c->len);
        char buf[VG_PREFIX_STRLEN];
        CHECK(vg_prefix_format(&p, buf, sizeof(buf)) > 0);
        CHECK_EQ_STR(buf, c->want);

        /* round trip */
        vg_prefix_t q;
        CHECK_EQ_INT(vg_prefix_parse(buf, &q), 0);
        CHECK(vg_prefix_equal(&p, &q));
    }

    for (size_t i = 0; i < sizeof(bad_cases) / sizeof(bad_cases[0]); i++) {
        vg_prefix_t p;
        if (vg_prefix_parse(bad_cases[i], &p) == 0) {
            t_failures++;
            fprintf(stderr, "FAIL: expected parse error for \"%s\"\n", bad_cases[i]);
        }
        t_checks++;
    }

    /* covers: equal, more-specific, unrelated, cross-family */
    vg_prefix_t a, b;
    vg_prefix_parse("10.0.0.0/8", &a);
    vg_prefix_parse("10.1.0.0/16", &b);
    CHECK(vg_prefix_covers(&a, &b));
    CHECK(!vg_prefix_covers(&b, &a));
    CHECK(vg_prefix_covers(&a, &a));
    vg_prefix_parse("11.0.0.0/8", &b);
    CHECK(!vg_prefix_covers(&a, &b));
    vg_prefix_parse("0.0.0.0/0", &b);
    CHECK(vg_prefix_covers(&b, &a));
    vg_prefix_parse("2001:db8::/32", &b);
    CHECK(!vg_prefix_covers(&a, &b)); /* cross family */
    vg_prefix_t v6a, v6b;
    vg_prefix_parse("2001:db8::/32", &v6a);
    vg_prefix_parse("2001:db8:1234::/48", &v6b);
    CHECK(vg_prefix_covers(&v6a, &v6b));
    CHECK(!vg_prefix_covers(&v6b, &v6a));
    /* non-byte-aligned boundary */
    vg_prefix_t p25, p26in, p26out;
    vg_prefix_parse("192.0.2.128/25", &p25);
    vg_prefix_parse("192.0.2.192/26", &p26in);
    vg_prefix_parse("192.0.2.0/26", &p26out);
    CHECK(vg_prefix_covers(&p25, &p26in));
    CHECK(!vg_prefix_covers(&p25, &p26out));

    /* format buffer too small */
    char tiny[4];
    CHECK_EQ_INT(vg_prefix_format(&a, tiny, sizeof(tiny)), -1);

    TEST_MAIN_END();
}
