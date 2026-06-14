#include "../src/util/sbuf.h"
#include "test.h"

int main(void) {
    vg_sbuf_t b;
    vg_sbuf_init(&b);
    vg_sbuf_puts(&b, "hello ");
    vg_sbuf_printf(&b, "world %d", 42);
    CHECK_EQ_STR(b.data, "hello world 42");
    CHECK_EQ_INT((int)b.len, 14);
    vg_sbuf_free(&b);

    /* growth across many appends */
    vg_sbuf_init(&b);
    for (int i = 0; i < 5000; i++) vg_sbuf_puts(&b, "x");
    CHECK_EQ_INT((int)b.len, 5000);
    vg_sbuf_free(&b);

    /* JSON escaping */
    vg_sbuf_init(&b);
    vg_sbuf_puts(&b, "{\"s\":\"");
    vg_sbuf_json(&b, "a\"b\\c\nd");
    vg_sbuf_puts(&b, "\"}");
    CHECK_EQ_STR(b.data, "{\"s\":\"a\\\"b\\\\c\\u000ad\"}");
    vg_sbuf_free(&b);

    TEST_MAIN_END();
}
