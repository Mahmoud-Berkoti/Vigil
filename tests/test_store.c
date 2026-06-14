#include "../src/alert/store.h"
#include "test.h"

static vg_alert_t mk(vg_alert_type_t type, vg_severity_t sev, const char *pfx,
                     double ts, uint32_t exp_asn, uint32_t obs_asn) {
    vg_alert_t a;
    memset(&a, 0, sizeof(a));
    a.type = type;
    a.severity = sev;
    a.timestamp = ts;
    if (pfx) vg_prefix_parse(pfx, &a.prefix);
    a.expected_asn = exp_asn;
    a.observed_asn = obs_asn;
    snprintf(a.peer, sizeof(a.peer), "peer1");
    snprintf(a.summary, sizeof(a.summary), "test alert");
    snprintf(a.evidence, sizeof(a.evidence), "{\"k\":1}");
    return a;
}

#define MAX_Q 32
static vg_alert_t got[MAX_Q];
static int n_got;
static void collect(const vg_alert_t *a, void *user) {
    (void)user;
    if (n_got < MAX_Q) got[n_got++] = *a;
}

int main(void) {
    vg_store_t *s = vg_store_open(":memory:");
    CHECK(s != NULL);

    vg_alert_t a1 = mk(VG_ALERT_HIJACK, VG_SEV_CRITICAL, "192.0.2.0/24", 100, 64500, 64666);
    CHECK_EQ_INT(vg_store_insert(s, &a1), 0);
    CHECK(a1.id > 0);
    vg_alert_t a2 = mk(VG_ALERT_SPIKE, VG_SEV_INFO, "198.51.100.0/24", 200, 0, 0);
    CHECK_EQ_INT(vg_store_insert(s, &a2), 0);
    vg_alert_t a3 = mk(VG_ALERT_HIJACK, VG_SEV_WARNING, "192.0.2.0/24", 300, 1, 2);
    CHECK_EQ_INT(vg_store_insert(s, &a3), 0);
    CHECK(a3.id > a1.id);

    /* query all, newest first */
    n_got = 0;
    vg_store_filter_t f = {-1, -1, 0, NULL, 100};
    CHECK_EQ_INT(vg_store_query(s, &f, collect, NULL), 3);
    CHECK(got[0].timestamp == 300.0);
    CHECK(got[2].timestamp == 100.0);

    /* filter by type */
    n_got = 0;
    f.type = VG_ALERT_HIJACK;
    CHECK_EQ_INT(vg_store_query(s, &f, collect, NULL), 2);

    /* filter by prefix */
    n_got = 0;
    f = (vg_store_filter_t){-1, -1, 0, "198.51.100.0/24", 100};
    CHECK_EQ_INT(vg_store_query(s, &f, collect, NULL), 1);
    char pfx[VG_PREFIX_STRLEN];
    vg_prefix_format(&got[0].prefix, pfx, sizeof(pfx));
    CHECK_EQ_STR(pfx, "198.51.100.0/24");

    /* filter by since */
    n_got = 0;
    f = (vg_store_filter_t){-1, -1, 250, NULL, 100};
    CHECK_EQ_INT(vg_store_query(s, &f, collect, NULL), 1);
    CHECK(got[0].timestamp == 300.0);

    /* filter by minimum severity */
    n_got = 0;
    f = (vg_store_filter_t){-1, VG_SEV_CRITICAL, 0, NULL, 100};
    CHECK_EQ_INT(vg_store_query(s, &f, collect, NULL), 1);
    CHECK((int)got[0].severity == (int)VG_SEV_CRITICAL);

    /* limit */
    n_got = 0;
    f = (vg_store_filter_t){-1, -1, 0, NULL, 1};
    CHECK_EQ_INT(vg_store_query(s, &f, collect, NULL), 1);

    /* round-trip fidelity of a full row */
    n_got = 0;
    f = (vg_store_filter_t){-1, -1, 0, NULL, 1};
    vg_store_query(s, &f, collect, NULL);
    CHECK_EQ_INT(got[0].expected_asn, 1);
    CHECK_EQ_INT(got[0].observed_asn, 2);
    CHECK_EQ_STR(got[0].peer, "peer1");
    CHECK_EQ_STR(got[0].summary, "test alert");
    CHECK_EQ_STR(got[0].evidence, "{\"k\":1}");

    uint64_t counts[5];
    CHECK_EQ_INT(vg_store_counts(s, counts), 0);
    CHECK_EQ_INT((int)counts[VG_ALERT_HIJACK], 2);
    CHECK_EQ_INT((int)counts[VG_ALERT_SPIKE], 1);
    CHECK_EQ_INT((int)counts[VG_ALERT_LEAK], 0);

    vg_store_close(s);
    TEST_MAIN_END();
}
