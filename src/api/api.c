#include "api.h"

#include "../metrics/metrics.h"
#include "../util/sbuf.h"
#include "http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct vg_api {
    vg_http_server_t *http;
    vg_rib_t         *rib;
    vg_engine_t      *engine;
    vg_store_t       *store;
    vg_rislive_t     *live;
    char              web_dir[512];
};

static void set_json(vg_http_res_t *res, int status, vg_sbuf_t *b) {
    res->status = status;
    res->content_type = "application/json";
    res->body = b->data ? b->data : strdup("");
    res->body_len = b->len;
    b->data = NULL; /* ownership transferred */
}

/* ---- GET /api/v1/prefixes/{prefix} ---------------------------------- */

typedef struct {
    vg_sbuf_t *b;
    int        n;
} route_walk_ctx_t;

static void route_json(const vg_prefix_t *p, const vg_rib_route_t *r, void *user) {
    route_walk_ctx_t *c = user;
    char pfx[VG_PREFIX_STRLEN], path[512];
    vg_prefix_format(p, pfx, sizeof(pfx));
    vg_aspath_format(&r->path, path, sizeof(path));
    if (c->n++ > 0) vg_sbuf_puts(c->b, ",");
    vg_sbuf_printf(c->b,
                  "{\"peer\":\"%s\",\"peer_asn\":%u,\"as_path\":\"%s\","
                  "\"origin_asn\":%u,\"origin_attr\":%u,\"last_updated\":%.3f}",
                  r->peer, r->peer_asn, path, vg_aspath_origin(&r->path),
                  r->origin_attr, r->last_updated);
}

static void history_json(const vg_rib_change_t *c, void *user) {
    route_walk_ctx_t *ctx = user;
    if (ctx->n++ > 0) vg_sbuf_puts(ctx->b, ",");
    vg_sbuf_printf(ctx->b,
                  "{\"timestamp\":%.3f,\"kind\":\"%s\",\"origin_asn\":%u,"
                  "\"peer\":\"%s\",\"peer_asn\":%u}",
                  c->ts, c->kind == VG_EV_ANNOUNCE ? "announce" : "withdraw",
                  c->origin_asn, c->peer, c->peer_asn);
}

static void h_prefix(const vg_http_req_t *req, vg_http_res_t *res, void *user) {
    vg_api_t *api = user;
    const char *tail = vg_http_path_tail(req->path, "/api/v1/prefixes/");
    vg_prefix_t p;
    if (!tail || vg_prefix_parse(tail, &p) != 0) {
        vg_sbuf_t b;
        vg_sbuf_init(&b);
        vg_sbuf_puts(&b, "{\"error\":\"invalid prefix\"}");
        set_json(res, 400, &b);
        return;
    }

    vg_sbuf_t b;
    vg_sbuf_init(&b);
    char pfx[VG_PREFIX_STRLEN];
    vg_prefix_format(&p, pfx, sizeof(pfx));
    vg_sbuf_printf(&b, "{\"prefix\":\"%s\",\"dominant_origin\":%u,\"routes\":[",
                  pfx, vg_rib_origin_of(api->rib, &p));
    route_walk_ctx_t ctx = {&b, 0};
    vg_rib_lookup(api->rib, &p, route_json, &ctx);
    vg_sbuf_puts(&b, "],\"history\":[");
    ctx.n = 0;
    vg_rib_history(api->rib, &p, history_json, &ctx);
    vg_sbuf_puts(&b, "]}");
    set_json(res, 200, &b);
}

/* ---- GET /api/v1/asns/{asn}/prefixes -------------------------------- */

static void origin_prefix_json(const vg_prefix_t *p, const vg_rib_route_t *r,
                               void *user) {
    route_walk_ctx_t *c = user;
    char pfx[VG_PREFIX_STRLEN];
    vg_prefix_format(p, pfx, sizeof(pfx));
    if (c->n++ > 0) vg_sbuf_puts(c->b, ",");
    vg_sbuf_printf(c->b, "{\"prefix\":\"%s\",\"peer\":\"%s\"}", pfx, r->peer);
}

static void h_asn_prefixes(const vg_http_req_t *req, vg_http_res_t *res, void *user) {
    vg_api_t *api = user;
    const char *tail = vg_http_path_tail(req->path, "/api/v1/asns/");
    uint32_t asn = tail ? (uint32_t)strtoul(tail, NULL, 10) : 0;

    vg_sbuf_t b;
    vg_sbuf_init(&b);
    vg_sbuf_printf(&b, "{\"asn\":%u,\"prefixes\":[", asn);
    route_walk_ctx_t ctx = {&b, 0};
    vg_rib_by_origin(api->rib, asn, origin_prefix_json, &ctx);
    vg_sbuf_puts(&b, "]}");
    set_json(res, 200, &b);
}

/* ---- GET /api/v1/alerts ----------------------------------------------- */

static void alert_json(const vg_alert_t *a, void *user) {
    route_walk_ctx_t *c = user;
    char pfx[VG_PREFIX_STRLEN] = "";
    if (a->prefix.family != 0) vg_prefix_format(&a->prefix, pfx, sizeof(pfx));
    if (c->n++ > 0) vg_sbuf_puts(c->b, ",");
    vg_sbuf_printf(c->b,
                  "{\"id\":%lld,\"timestamp\":%.3f,\"type\":\"%s\","
                  "\"severity\":\"%s\",\"prefix\":\"%s\",\"expected_asn\":%u,"
                  "\"observed_asn\":%u,\"peer\":\"%s\",\"summary\":\"",
                  (long long)a->id, a->timestamp, vg_alert_type_str(a->type),
                  vg_severity_str(a->severity), pfx, a->expected_asn,
                  a->observed_asn, a->peer);
    vg_sbuf_json(c->b, a->summary);
    vg_sbuf_puts(c->b, "\",\"evidence\":");
    vg_sbuf_puts(c->b, a->evidence[0] == '{' ? a->evidence : "null");
    vg_sbuf_puts(c->b, "}");
}

static void h_alerts(const vg_http_req_t *req, vg_http_res_t *res, void *user) {
    vg_api_t *api = user;
    vg_store_filter_t f = {-1, -1, 0, NULL, 100};

    char val[64];
    if (vg_http_query_get(req->query, "type", val, sizeof(val))) {
        for (int i = 0; i <= VG_ALERT_SPIKE; i++)
            if (strcmp(vg_alert_type_str((vg_alert_type_t)i), val) == 0) f.type = i;
    }
    if (vg_http_query_get(req->query, "severity", val, sizeof(val))) {
        for (int i = 0; i <= VG_SEV_CRITICAL; i++)
            if (strcmp(vg_severity_str((vg_severity_t)i), val) == 0) f.severity = i;
    }
    if (vg_http_query_get(req->query, "since", val, sizeof(val)))
        f.since = atof(val);
    if (vg_http_query_get(req->query, "limit", val, sizeof(val)))
        f.limit = atoi(val);
    char prefix_val[VG_PREFIX_STRLEN];
    if (vg_http_query_get(req->query, "prefix", prefix_val, sizeof(prefix_val)))
        f.prefix = prefix_val;

    vg_sbuf_t b;
    vg_sbuf_init(&b);
    vg_sbuf_puts(&b, "{\"alerts\":[");
    route_walk_ctx_t ctx = {&b, 0};
    int n = vg_store_query(api->store, &f, alert_json, &ctx);
    vg_sbuf_printf(&b, "],\"count\":%d}", n < 0 ? 0 : n);
    set_json(res, 200, &b);
}

/* ---- GET /api/v1/stats ------------------------------------------------ */

static void h_stats(const vg_http_req_t *req, vg_http_res_t *res, void *user) {
    (void)req;
    vg_api_t *api = user;

    vg_rib_stats_t rs;
    vg_rib_stats(api->rib, &rs);
    vg_engine_stats_t es;
    vg_engine_stats(api->engine, &es);
    uint64_t counts[5];
    vg_store_counts(api->store, counts);

    vg_sbuf_t b;
    vg_sbuf_init(&b);
    vg_sbuf_printf(&b,
                  "{\"rib\":{\"prefixes\":%llu,\"routes\":%llu,"
                  "\"events_applied\":%llu,\"memory_bytes\":%llu},"
                  "\"engine\":{\"events\":%llu,\"suppressed\":%llu},"
                  "\"alerts_total\":{\"hijack\":%llu,\"subprefix\":%llu,"
                  "\"leak\":%llu,\"rpki_invalid\":%llu,\"spike\":%llu}",
                  (unsigned long long)rs.prefixes, (unsigned long long)rs.routes,
                  (unsigned long long)rs.events_applied,
                  (unsigned long long)rs.mem_bytes,
                  (unsigned long long)es.events, (unsigned long long)es.suppressed,
                  (unsigned long long)counts[0], (unsigned long long)counts[1],
                  (unsigned long long)counts[2], (unsigned long long)counts[3],
                  (unsigned long long)counts[4]);
    if (api->live) {
        vg_rislive_stats_t ls;
        vg_rislive_stats(api->live, &ls);
        vg_sbuf_printf(&b,
                      ",\"rislive\":{\"connected\":%s,\"messages\":%llu,"
                      "\"events\":%llu,\"parse_errors\":%llu,\"reconnects\":%llu}",
                      ls.connected ? "true" : "false",
                      (unsigned long long)ls.messages, (unsigned long long)ls.events,
                      (unsigned long long)ls.parse_errors,
                      (unsigned long long)ls.reconnects);
    }
    vg_sbuf_puts(&b, "}");
    set_json(res, 200, &b);
}

/* ---- GET /metrics ------------------------------------------------------ */

static void h_metrics(const vg_http_req_t *req, vg_http_res_t *res, void *user) {
    (void)req;
    vg_api_t *api = user;
    char *buf = malloc(1 << 16);
    size_t n = vg_metrics_render(api->rib, api->engine, api->live, buf, 1 << 16);
    res->status = 200;
    res->content_type = "text/plain; version=0.0.4";
    res->body = buf;
    res->body_len = n;
}

/* ---- static dashboard --------------------------------------------------- */

static void h_dashboard(const vg_http_req_t *req, vg_http_res_t *res, void *user) {
    vg_api_t *api = user;
    const char *rel = strcmp(req->path, "/") == 0 ? "index.html" : req->path + 1;
    /* no "..": dashboard files are flat, this is enough to stay inside web_dir */
    if (strstr(rel, "..")) {
        res->status = 400;
        res->body = strdup("bad path");
        res->body_len = strlen(res->body);
        return;
    }
    char full[768];
    snprintf(full, sizeof(full), "%s/%s", api->web_dir, rel);
    FILE *f = fopen(full, "rb");
    if (!f) {
        const char *msg = "{\"error\":\"not found\"}";
        res->status = 404;
        res->content_type = "application/json";
        res->body = strdup(msg);
        res->body_len = strlen(msg);
        return;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)sz);
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    res->status = 200;
    res->content_type = strstr(rel, ".js")   ? "application/javascript"
                        : strstr(rel, ".css") ? "text/css"
                                              : "text/html";
    res->body = buf;
    res->body_len = rd;
}

/* ---- lifecycle ---------------------------------------------------------- */

vg_api_t *vg_api_start(int port, vg_rib_t *rib, vg_engine_t *engine,
                       vg_store_t *store, vg_rislive_t *live,
                       const char *web_dir) {
    vg_api_t *api = calloc(1, sizeof(*api));
    if (!api) return NULL;
    api->rib = rib;
    api->engine = engine;
    api->store = store;
    api->live = live;
    snprintf(api->web_dir, sizeof(api->web_dir), "%s", web_dir ? web_dir : "web");

    api->http = vg_http_server_new(port);
    if (!api->http) {
        free(api);
        return NULL;
    }
    vg_http_route(api->http, "GET", "/api/v1/prefixes/*", h_prefix, api);
    vg_http_route(api->http, "GET", "/api/v1/asns/*", h_asn_prefixes, api);
    vg_http_route(api->http, "GET", "/api/v1/alerts", h_alerts, api);
    vg_http_route(api->http, "GET", "/api/v1/stats", h_stats, api);
    vg_http_route(api->http, "GET", "/metrics", h_metrics, api);
    vg_http_route(api->http, "GET", "/*", h_dashboard, api);

    if (vg_http_server_start(api->http) != 0) {
        free(api->http);
        free(api);
        return NULL;
    }
    return api;
}

void vg_api_stop(vg_api_t *api) {
    if (!api) return;
    vg_http_server_stop(api->http);
    free(api->http);
    free(api);
}
