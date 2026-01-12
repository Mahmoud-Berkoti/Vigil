#include "../src/vigil.h"
#include "test.h"

int main(void) {
    vg_aspath_t p;

    CHECK_EQ_INT(vg_aspath_parse("64500 64510 64520", &p), 0);
    CHECK_EQ_INT(p.count, 3);
    CHECK_EQ_INT(vg_aspath_origin(&p), 64520);

    char buf[256];
    CHECK(vg_aspath_format(&p, buf, sizeof(buf)) > 0);
    CHECK_EQ_STR(buf, "64500 64510 64520");

    /* 4-byte ASN */
    CHECK_EQ_INT(vg_aspath_parse("4200000001", &p), 0);
    CHECK_EQ_INT(vg_aspath_origin(&p), 4200000001u);

    /* empty path */
    CHECK_EQ_INT(vg_aspath_parse("", &p), 0);
    CHECK_EQ_INT(p.count, 0);
    CHECK_EQ_INT(vg_aspath_origin(&p), 0);
    CHECK_EQ_INT(vg_aspath_format(&p, buf, sizeof(buf)), 0);
    CHECK_EQ_STR(buf, "");

    /* bad input */
    CHECK_EQ_INT(vg_aspath_parse("64500 x", &p), -1);
    CHECK_EQ_INT(vg_aspath_parse("99999999999", &p), -1);

    /* buffer too small */
    vg_aspath_parse("64500 64510", &p);
    char tiny[6];
    CHECK_EQ_INT(vg_aspath_format(&p, tiny, sizeof(tiny)), -1);

    TEST_MAIN_END();
}
