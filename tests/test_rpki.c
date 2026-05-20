#include "../src/detect/detect.h"
#include "../src/rpki/rpki.h"
#include "test.h"

static vg_rov_state_t check(vg_rpki_t *r, const char *pfx, uint32_t asn) {
    vg_prefix_t p;
    if (vg_prefix_parse(pfx, &p) != 0) return (vg_rov_state_t)99;
    return vg_rpki_validate(r, &p, asn);
}

#define MAX_AL 16
static vg_alert_t alerts[MAX_AL];
static int n_alerts;
static void capture_alert(const vg_alert_t *a, void *user) {
    (void)user;
    if (n_alerts < MAX_AL) alerts[n_alerts++] = *a;
}

int main(void) {
    vg_rpki_t *r = vg_rpki_load("data/vrp/vrp-sample.json");
    CHECK(r != NULL);
    if (!r) TEST_MAIN_END();
    CHECK_EQ_INT((int)vg_rpki_count(r), 8);

    /* exact match */
    CHECK_EQ_INT(check(r, "1.1.1.0/24", 13335), VG_ROV_VALID);
    /* wrong origin */
    CHECK_EQ_INT(check(r, "1.1.1.0/24", 64666), VG_ROV_INVALID);
    /* no covering VRP */
    CHECK_EQ_INT(check(r, "9.9.9.0/24", 19281), VG_ROV_NOTFOUND);

    /* maxLength: /28 allowed under 192.0.2.0/24-28, /29 is not */
    CHECK_EQ_INT(check(r, "192.0.2.0/24", 64500), VG_ROV_VALID);
    CHECK_EQ_INT(check(r, "192.0.2.16/28", 64500), VG_ROV_VALID);
    CHECK_EQ_INT(check(r, "192.0.2.16/29", 64500), VG_ROV_INVALID);

    /* absent maxLength defaults to the ROA prefix length */
    CHECK_EQ_INT(check(r, "198.51.100.0/24", 64501), VG_ROV_VALID);
    CHECK_EQ_INT(check(r, "198.51.100.0/25", 64501), VG_ROV_INVALID);

    /* multiple VRPs on one prefix: either origin can be valid, with
     * its own maxLength */
    CHECK_EQ_INT(check(r, "203.0.113.0/24", 64500), VG_ROV_VALID);
    CHECK_EQ_INT(check(r, "203.0.113.0/24", 64502), VG_ROV_VALID);
    CHECK_EQ_INT(check(r, "203.0.113.0/26", 64500), VG_ROV_INVALID);
    CHECK_EQ_INT(check(r, "203.0.113.0/26", 64502), VG_ROV_VALID);
    CHECK_EQ_INT(check(r, "203.0.113.0/24", 64666), VG_ROV_INVALID);

    /* AS0 ROA (RFC 7607) poisons the prefix: nothing can be valid */
    CHECK_EQ_INT(check(r, "10.66.0.0/16", 0), VG_ROV_INVALID);
    CHECK_EQ_INT(check(r, "10.66.0.0/16", 64500), VG_ROV_INVALID);
    CHECK_EQ_INT(check(r, "10.66.5.0/24", 64500), VG_ROV_INVALID);

    /* IPv6 with maxLength range */
    CHECK_EQ_INT(check(r, "2001:db8::/32", 64510), VG_ROV_VALID);
    CHECK_EQ_INT(check(r, "2001:db8:1::/48", 64510), VG_ROV_VALID);
    CHECK_EQ_INT(check(r, "2001:db8:1::/49", 64510), VG_ROV_INVALID);
    CHECK_EQ_INT(check(r, "2001:db9::/32", 64510), VG_ROV_NOTFOUND);

    /* a covering ROA affects more-specifics (INVALID, not NOTFOUND) */
    CHECK_EQ_INT(check(r, "1.1.1.128/25", 13335), VG_ROV_INVALID);
    /* ...but not less-specifics (a /23 is not covered by the /24 ROA) */
    CHECK_EQ_INT(check(r, "1.1.0.0/23", 13335), VG_ROV_NOTFOUND);

    /* ---- engine integration: rpki detector fires on invalids ---- */
    vg_config_t cfg;
    vg_config_defaults(&cfg);
    vg_rib_t *rib = vg_rib_new();
    vg_engine_t *e = vg_engine_new(&cfg, rib, capture_alert, NULL);
    vg_engine_set_rpki(e, r);
    n_alerts = 0;

    vg_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.kind = VG_EV_ANNOUNCE;
    ev.timestamp = 1000;
    snprintf(ev.peer, sizeof(ev.peer), "p1");
    ev.peer_asn = 6939;
    snprintf(ev.source, sizeof(ev.source), "test");

    /* valid announcement: silent */
    vg_prefix_parse("8.8.8.0/24", &ev.prefix);
    vg_aspath_parse("6939 15169", &ev.path);
    vg_engine_event(e, &ev);
    CHECK_EQ_INT(n_alerts, 0);

    /* notfound: silent */
    vg_prefix_parse("9.9.9.0/24", &ev.prefix);
    vg_aspath_parse("6939 19281", &ev.path);
    vg_engine_event(e, &ev);
    CHECK_EQ_INT(n_alerts, 0);

    /* invalid: alert */
    vg_prefix_parse("8.8.8.0/24", &ev.prefix);
    vg_aspath_parse("6939 64666", &ev.path);
    ev.timestamp = 1010;
    vg_engine_event(e, &ev);
    CHECK_EQ_INT(n_alerts, 1);
    CHECK_EQ_INT((int)alerts[0].type, (int)VG_ALERT_RPKI_INVALID);
    CHECK_EQ_INT(alerts[0].observed_asn, 64666);
    CHECK(strstr(alerts[0].summary, "RPKI-invalid") != NULL);

    vg_engine_free(e);
    vg_rib_free(rib);

    /* malformed file handling */
    CHECK(vg_rpki_load("/nonexistent.json") == NULL);
    vg_rpki_free(r);

    TEST_MAIN_END();
}
