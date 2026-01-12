#include "../src/core/config.h"
#include "test.h"

#include <stdio.h>
#include <unistd.h>

static const char *SAMPLE =
    "# vigil test config\n"
    "api_port = 9999\n"
    "mrt_file = data/fixtures/updates.mrt\n"
    "replay_speed = 2.5\n"
    "rislive_enabled = true\n"
    "vrp_file = data/vrp/vrp.json\n"
    "watch = 192.0.2.0/24 64500\n"
    "watch = 2001:db8::/32\n"
    "spike_factor = 5\n";

int main(void) {
    char path[] = "/tmp/vigil_test_config_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    FILE *f = fdopen(fd, "w");
    fputs(SAMPLE, f);
    fclose(f);

    vg_config_t c;
    vg_config_defaults(&c);
    CHECK_EQ_INT(c.api_port, 8080); /* default before load */

    CHECK_EQ_INT(vg_config_load(&c, path), 0);
    CHECK_EQ_INT(c.api_port, 9999);
    CHECK_EQ_STR(c.mrt_file, "data/fixtures/updates.mrt");
    CHECK(c.replay_speed == 2.5);
    CHECK(c.rislive_enabled);
    CHECK_EQ_STR(c.vrp_file, "data/vrp/vrp.json");
    CHECK_EQ_INT(c.n_watch, 2);
    CHECK_EQ_INT(c.watch_origin[0], 64500);
    CHECK_EQ_INT(c.watch_origin[1], 0); /* learn-from-baseline */
    CHECK(c.spike_factor == 5);

    char buf[VG_PREFIX_STRLEN];
    vg_prefix_format(&c.watch_prefix[0], buf, sizeof(buf));
    CHECK_EQ_STR(buf, "192.0.2.0/24");
    vg_prefix_format(&c.watch_prefix[1], buf, sizeof(buf));
    CHECK_EQ_STR(buf, "2001:db8::/32");

    /* unknown key is an error */
    f = fopen(path, "w");
    fputs("nonsense_key = 1\n", f);
    fclose(f);
    vg_config_defaults(&c);
    CHECK_EQ_INT(vg_config_load(&c, path), -1);

    /* bad watch prefix is an error */
    f = fopen(path, "w");
    fputs("watch = 999.0.0.0/8\n", f);
    fclose(f);
    vg_config_defaults(&c);
    CHECK_EQ_INT(vg_config_load(&c, path), -1);

    unlink(path);

    /* missing file */
    vg_config_defaults(&c);
    CHECK_EQ_INT(vg_config_load(&c, "/nonexistent/vigil.conf"), -1);

    TEST_MAIN_END();
}
