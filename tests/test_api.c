#include "../src/alert/store.h"
#include "../src/api/api.h"
#include "../src/detect/detect.h"
#include "../src/rib/rib.h"
#include "test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 18099

/* minimal blocking HTTP GET client for testing our own server */
typedef struct {
    int  status;
    char body[16384];
    size_t body_len;
} http_resp_t;

static int http_get(const char *path, http_resp_t *out) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    char req[1024];
    int n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                     path);
    if (send(fd, req, (size_t)n, 0) < 0) { close(fd); return -1; }

    char buf[65536];
    size_t total = 0;
    ssize_t got;
    while (total < sizeof(buf) - 1 &&
           (got = recv(fd, buf + total, sizeof(buf) - 1 - total, 0)) > 0)
        total += (size_t)got;
    close(fd);
    buf[total] = '\0';

    if (sscanf(buf, "HTTP/1.1 %d", &out->status) != 1) return -1;
    char *body = strstr(buf, "\r\n\r\n");
    if (!body) return -1;
    body += 4;
    size_t blen = total - (size_t)(body - buf);
    if (blen >= sizeof(out->body)) blen = sizeof(out->body) - 1;
    memcpy(out->body, body, blen);
    out->body[blen] = '\0';
    out->body_len = blen;
    return 0;
}

/* try connecting a few times: server thread needs a moment to bind */
static void wait_for_server(void) {
    for (int i = 0; i < 50; i++) {
        http_resp_t r;
        if (http_get("/api/v1/stats", &r) == 0) return;
        usleep(20000);
    }
}

static void store_sink(const vg_alert_t *a, void *user) {
    vg_store_t *store = user;
    vg_alert_t copy = *a;
    vg_store_insert(store, &copy);
}

int main(void) {
    vg_config_t cfg;
    vg_config_defaults(&cfg);
    cfg.n_watch = 1;
    vg_prefix_parse("192.0.2.0/24", &cfg.watch_prefix[0]);
    cfg.watch_origin[0] = 64500;

    vg_rib_t *rib = vg_rib_new();
    vg_store_t *store = vg_store_open(":memory:");
    CHECK(rib && store);

    vg_engine_t *engine = vg_engine_new(&cfg, rib, store_sink, store);
    CHECK(engine != NULL);

    /* clean announce, then a hijack */
    vg_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.kind = VG_EV_ANNOUNCE;
    vg_prefix_parse("192.0.2.0/24", &ev.prefix);
    vg_aspath_parse("6939 64500", &ev.path);
    ev.origin_attr = VG_ORIGIN_IGP;
    ev.timestamp = 1000;
    snprintf(ev.peer, sizeof(ev.peer), "203.0.113.1");
    ev.peer_asn = 6939;
    snprintf(ev.source, sizeof(ev.source), "test");
    vg_engine_event(engine, &ev);

    vg_aspath_parse("1299 64666", &ev.path);
    ev.timestamp = 1010;
    ev.peer_asn = 1299;
    snprintf(ev.peer, sizeof(ev.peer), "203.0.113.2");
    vg_engine_event(engine, &ev);

    vg_api_t *api = vg_api_start(PORT, rib, engine, store, NULL, "web");
    CHECK(api != NULL);
    wait_for_server();

    http_resp_t r;

    /* /api/v1/stats */
    CHECK_EQ_INT(http_get("/api/v1/stats", &r), 0);
    CHECK_EQ_INT(r.status, 200);
    CHECK(strstr(r.body, "\"prefixes\":1") != NULL);
    CHECK(strstr(r.body, "\"hijack\":1") != NULL);

    /* /api/v1/prefixes/{p} */
    CHECK_EQ_INT(http_get("/api/v1/prefixes/192.0.2.0%2F24", &r), 0);
    CHECK_EQ_INT(r.status, 200);
    CHECK(strstr(r.body, "\"dominant_origin\":64500") != NULL);
    CHECK(strstr(r.body, "\"peer_asn\":6939") != NULL);
    CHECK(strstr(r.body, "\"peer_asn\":1299") != NULL);
    CHECK(strstr(r.body, "\"history\":[") != NULL);

    /* invalid prefix -> 400 */
    CHECK_EQ_INT(http_get("/api/v1/prefixes/not-a-prefix", &r), 0);
    CHECK_EQ_INT(r.status, 400);

    /* /api/v1/asns/{asn}/prefixes */
    CHECK_EQ_INT(http_get("/api/v1/asns/64500/prefixes", &r), 0);
    CHECK_EQ_INT(r.status, 200);
    CHECK(strstr(r.body, "192.0.2.0/24") != NULL);

    /* /api/v1/alerts filtered by type */
    CHECK_EQ_INT(http_get("/api/v1/alerts?type=hijack", &r), 0);
    CHECK_EQ_INT(r.status, 200);
    CHECK(strstr(r.body, "\"count\":1") != NULL);
    CHECK(strstr(r.body, "\"observed_asn\":64666") != NULL);

    /* /api/v1/alerts filtered by prefix + limit */
    CHECK_EQ_INT(http_get("/api/v1/alerts?prefix=192.0.2.0%2F24&limit=1", &r), 0);
    CHECK(strstr(r.body, "\"count\":1") != NULL);

    /* nonexistent route -> 404 */
    CHECK_EQ_INT(http_get("/api/v1/nope", &r), 0);
    CHECK_EQ_INT(r.status, 404);

    /* /metrics */
    CHECK_EQ_INT(http_get("/metrics", &r), 0);
    CHECK_EQ_INT(r.status, 200);
    CHECK(strstr(r.body, "vigil_rib_prefixes 1") != NULL);
    CHECK(strstr(r.body, "vigil_alerts_total{type=\"hijack\"} 1") != NULL);

    /* dashboard root serves index.html */
    CHECK_EQ_INT(http_get("/", &r), 0);
    CHECK_EQ_INT(r.status, 200);
    CHECK(strstr(r.body, "Vigil") != NULL);

    /* dashboard path traversal is rejected */
    CHECK_EQ_INT(http_get("/../Makefile", &r), 0);
    CHECK(r.status == 400 || r.status == 404);

    vg_api_stop(api);
    vg_engine_free(engine);
    vg_store_close(store);
    vg_rib_free(rib);

    TEST_MAIN_END();
}
