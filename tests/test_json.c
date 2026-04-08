#include "../src/util/json.h"
#include "test.h"

int main(void) {
    /* scalars, nesting, escapes */
    const char *doc =
        "{\"a\":1.5,\"b\":\"hi\\nthere \\u00e9\",\"c\":[1,2,[3]],"
        "\"d\":{\"e\":true,\"f\":null},\"neg\":-42,\"exp\":1e3,"
        "\"asn\":\"6939\"}";
    vg_json_t *r = vg_json_parse(doc, strlen(doc));
    CHECK(r != NULL);
    if (r) {
        CHECK_EQ_INT(r->type, VG_JSON_OBJECT);
        CHECK_EQ_INT((int)r->len, 7);
        CHECK(vg_json_num(r, "a", 0) == 1.5);
        CHECK_EQ_STR(vg_json_str(r, "b", ""), "hi\nthere \xc3\xa9");
        const vg_json_t *c = vg_json_get(r, "c");
        CHECK(c && c->type == VG_JSON_ARRAY && c->len == 3);
        const vg_json_t *third = c->child->next->next;
        CHECK(third && third->type == VG_JSON_ARRAY && third->len == 1);
        CHECK(third->child->num == 3.0);
        const vg_json_t *d = vg_json_get(r, "d");
        const vg_json_t *e = vg_json_get(d, "e");
        CHECK(e && e->type == VG_JSON_BOOL && e->boolean);
        const vg_json_t *f = vg_json_get(d, "f");
        CHECK(f && f->type == VG_JSON_NULL);
        CHECK(vg_json_num(r, "neg", 0) == -42.0);
        CHECK(vg_json_num(r, "exp", 0) == 1000.0);
        /* numeric string coercion (RIS Live sends peer_asn as string) */
        CHECK(vg_json_num(r, "asn", 0) == 6939.0);
        CHECK(vg_json_num(r, "missing", -1) == -1.0);
        CHECK(vg_json_str(r, "missing", "fb")[0] == 'f');
        vg_json_free(r);
    }

    /* malformed inputs must fail cleanly */
    const char *bad[] = {
        "",  "{", "}", "[1,", "{\"a\":}", "{\"a\" 1}", "{'a':1}",
        "[1 2]", "\"unterminated", "{\"a\":1}garbage", "nul", "01x",
        "{\"a\":\"\\q\"}", "[\"\\u12\"]",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (vg_json_parse(bad[i], strlen(bad[i])) != NULL) {
            t_failures++;
            fprintf(stderr, "FAIL: accepted malformed %s\n", bad[i]);
        }
        t_checks++;
    }

    /* depth bomb: 100 nested arrays must be rejected, not crash */
    char bomb[256];
    size_t n = 0;
    for (int i = 0; i < 100; i++) bomb[n++] = '[';
    for (int i = 0; i < 100; i++) bomb[n++] = ']';
    CHECK(vg_json_parse(bomb, n) == NULL);

    /* empty containers */
    r = vg_json_parse("[]", 2);
    CHECK(r && r->type == VG_JSON_ARRAY && r->len == 0);
    vg_json_free(r);
    r = vg_json_parse("{}", 2);
    CHECK(r && r->type == VG_JSON_OBJECT && r->len == 0);
    vg_json_free(r);

    TEST_MAIN_END();
}
