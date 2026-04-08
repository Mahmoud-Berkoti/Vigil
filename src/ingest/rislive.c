#include "rislive.h"

#include "../core/log.h"
#include "../util/json.h"

#include <curl/curl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LINE_MAX_LEN (1u << 20)

struct vg_rislive {
    vg_rislive_opts_t opts;
    vg_event_sink_fn  sink;
    void             *user;
    pthread_t         thread;
    atomic_bool       stop;
    atomic_bool       connected;
    _Atomic uint64_t  messages, events, parse_errors, reconnects;
    /* line reassembly buffer */
    char  *linebuf;
    size_t linelen;
};

/* ---- normalization ------------------------------------------------ */

/* RIS Live "path" arrays may nest an array for an AS_SET, e.g.
 * [6939, 3356, [64500, 64501]]. Flatten, marking set membership. */
static void flatten_path(const vg_json_t *arr, vg_aspath_t *out) {
    memset(out, 0, sizeof(*out));
    for (const vg_json_t *e = arr->child; e; e = e->next) {
        if (e->type == VG_JSON_NUMBER) {
            if (out->count < VG_ASPATH_MAX)
                out->as[out->count++] = (uint32_t)e->num;
            out->origin_from_set = false;
        } else if (e->type == VG_JSON_ARRAY) {
            for (const vg_json_t *s = e->child; s; s = s->next)
                if (s->type == VG_JSON_NUMBER && out->count < VG_ASPATH_MAX)
                    out->as[out->count++] = (uint32_t)s->num;
            out->origin_from_set = true;
        }
    }
}

static void set_next_hop(vg_event_t *ev, const char *nh) {
    if (!nh) return;
    vg_prefix_t tmp;
    char buf[80];
    /* reuse the prefix parser for address validation */
    snprintf(buf, sizeof(buf), "%s/%d", nh, strchr(nh, ':') ? 128 : 32);
    if (vg_prefix_parse(buf, &tmp) == 0) {
        ev->next_hop_family = tmp.family;
        memcpy(ev->next_hop, tmp.addr, 16);
    }
}

int vg_rislive_handle_line(const char *line, size_t len,
                           vg_event_sink_fn sink, void *user) {
    vg_json_t *root = vg_json_parse(line, len);
    if (!root) return -1;

    int emitted = 0;
    const char *mtype = vg_json_str(root, "type", "");
    if (strcmp(mtype, "ris_message") != 0) {
        /* ris_error / pong / etc. */
        if (strcmp(mtype, "ris_error") == 0)
            vg_log(VG_LOG_WARN, "rislive", "server error: %s",
                   vg_json_str(vg_json_get(root, "data") ? (const vg_json_t *)vg_json_get(root, "data") : root,
                               "message", "?"));
        vg_json_free(root);
        return 0;
    }

    const vg_json_t *data = vg_json_get(root, "data");
    if (!data || strcmp(vg_json_str(data, "type", ""), "UPDATE") != 0) {
        vg_json_free(root);
        return 0; /* OPEN/NOTIFICATION/KEEPALIVE/RIS_PEER_STATE */
    }

    vg_event_t base;
    memset(&base, 0, sizeof(base));
    base.timestamp = vg_json_num(data, "timestamp", 0);
    base.peer_asn = (uint32_t)vg_json_num(data, "peer_asn", 0);
    snprintf(base.peer, sizeof(base.peer), "%s", vg_json_str(data, "peer", "?"));
    snprintf(base.source, sizeof(base.source), "rislive");
    base.origin_attr = VG_ORIGIN_UNSET;

    /* attributes shared by all announcements in this message */
    vg_aspath_t path;
    memset(&path, 0, sizeof(path));
    const vg_json_t *jpath = vg_json_get(data, "path");
    if (jpath && jpath->type == VG_JSON_ARRAY) flatten_path(jpath, &path);

    const char *origin_s = vg_json_str(data, "origin", NULL);
    uint8_t origin_attr = VG_ORIGIN_UNSET;
    if (origin_s) {
        if (strcmp(origin_s, "igp") == 0) origin_attr = VG_ORIGIN_IGP;
        else if (strcmp(origin_s, "egp") == 0) origin_attr = VG_ORIGIN_EGP;
        else origin_attr = VG_ORIGIN_INCOMPLETE;
    }

    uint32_t communities[VG_MAX_COMMUNITIES];
    uint16_t n_communities = 0;
    const vg_json_t *comm = vg_json_get(data, "community");
    if (comm && comm->type == VG_JSON_ARRAY) {
        for (const vg_json_t *c = comm->child;
             c && n_communities < VG_MAX_COMMUNITIES; c = c->next) {
            if (c->type == VG_JSON_ARRAY && c->len == 2 &&
                c->child->type == VG_JSON_NUMBER &&
                c->child->next->type == VG_JSON_NUMBER) {
                communities[n_communities++] =
                    ((uint32_t)c->child->num << 16) |
                    ((uint32_t)c->child->next->num & 0xFFFF);
            }
        }
    }

    const vg_json_t *med = vg_json_get(data, "med");

    /* withdrawals: array of prefix strings */
    const vg_json_t *wd = vg_json_get(data, "withdrawals");
    if (wd && wd->type == VG_JSON_ARRAY) {
        for (const vg_json_t *w = wd->child; w; w = w->next) {
            if (w->type != VG_JSON_STRING) continue;
            vg_event_t ev = base;
            ev.kind = VG_EV_WITHDRAW;
            if (vg_prefix_parse(w->str, &ev.prefix) != 0) continue;
            sink(&ev, user);
            emitted++;
        }
    }

    /* announcements: [{next_hop, prefixes:[...]}] */
    const vg_json_t *ann = vg_json_get(data, "announcements");
    if (ann && ann->type == VG_JSON_ARRAY) {
        for (const vg_json_t *a = ann->child; a; a = a->next) {
            if (a->type != VG_JSON_OBJECT) continue;
            const vg_json_t *pfxs = vg_json_get(a, "prefixes");
            if (!pfxs || pfxs->type != VG_JSON_ARRAY) continue;
            for (const vg_json_t *p = pfxs->child; p; p = p->next) {
                if (p->type != VG_JSON_STRING) continue;
                vg_event_t ev = base;
                ev.kind = VG_EV_ANNOUNCE;
                if (vg_prefix_parse(p->str, &ev.prefix) != 0) continue;
                ev.path = path;
                ev.origin_attr = origin_attr;
                if (med && med->type == VG_JSON_NUMBER) {
                    ev.has_med = true;
                    ev.med = (uint32_t)med->num;
                }
                ev.n_communities = n_communities;
                memcpy(ev.communities, communities,
                       (size_t)n_communities * sizeof(uint32_t));
                set_next_hop(&ev, vg_json_str(a, "next_hop", NULL));
                sink(&ev, user);
                emitted++;
            }
        }
    }

    vg_json_free(root);
    return emitted;
}

/* ---- streaming ----------------------------------------------------- */

static size_t on_data(char *ptr, size_t size, size_t nmemb, void *userdata) {
    struct vg_rislive *c = userdata;
    size_t n = size * nmemb;
    if (atomic_load(&c->stop)) return 0; /* abort transfer */
    atomic_store(&c->connected, true);

    for (size_t i = 0; i < n; i++) {
        char ch = ptr[i];
        if (ch == '\n') {
            if (c->linelen > 0) {
                int rc = vg_rislive_handle_line(c->linebuf, c->linelen,
                                                c->sink, c->user);
                if (rc < 0) atomic_fetch_add(&c->parse_errors, 1);
                else {
                    atomic_fetch_add(&c->messages, 1);
                    atomic_fetch_add(&c->events, (uint64_t)rc);
                }
            }
            c->linelen = 0;
        } else if (c->linelen < LINE_MAX_LEN - 1) {
            c->linebuf[c->linelen++] = ch;
        } else {
            /* pathological line: drop it */
            c->linelen = 0;
            atomic_fetch_add(&c->parse_errors, 1);
        }
    }
    return n;
}

static void build_url(const vg_rislive_opts_t *o, char *url, size_t n) {
    size_t off = (size_t)snprintf(url, n,
        "https://ris-live.ripe.net/v1/stream/?format=json&client=vigil-monitor");
    if (o->host[0])
        off += (size_t)snprintf(url + off, n - off, "&host=%s", o->host);
    if (o->prefix[0]) {
        char enc[96];
        const char *s = o->prefix;
        size_t e = 0;
        for (; *s && e < sizeof(enc) - 4; s++) {
            if (*s == '/') { memcpy(enc + e, "%2F", 3); e += 3; }
            else enc[e++] = *s;
        }
        enc[e] = '\0';
        snprintf(url + off, n - off, "&prefix=%s&moreSpecific=true", enc);
    }
}

static void *run(void *arg) {
    struct vg_rislive *c = arg;
    char url[512];
    build_url(&c->opts, url, sizeof(url));

    int backoff = 1;
    while (!atomic_load(&c->stop)) {
        CURL *h = curl_easy_init();
        if (!h) break;
        curl_easy_setopt(h, CURLOPT_URL, url);
        curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, on_data);
        curl_easy_setopt(h, CURLOPT_WRITEDATA, c);
        curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 15L);
        /* fail if the stream stalls: < 1 byte/s for 60s */
        curl_easy_setopt(h, CURLOPT_LOW_SPEED_LIMIT, 1L);
        curl_easy_setopt(h, CURLOPT_LOW_SPEED_TIME, 60L);
        curl_easy_setopt(h, CURLOPT_USERAGENT, "vigil/1.0 (BGP monitor)");

        vg_log(VG_LOG_INFO, "rislive", "connecting: %s", url);
        CURLcode rc = curl_easy_perform(h);
        curl_easy_cleanup(h);
        atomic_store(&c->connected, false);
        c->linelen = 0;

        if (atomic_load(&c->stop)) break;
        atomic_fetch_add(&c->reconnects, 1);
        vg_log(VG_LOG_WARN, "rislive", "disconnected (%s), retry in %ds",
               curl_easy_strerror(rc), backoff);
        for (int i = 0; i < backoff * 10 && !atomic_load(&c->stop); i++)
            usleep(100000);
        backoff = backoff < 60 ? backoff * 2 : 60;
    }
    return NULL;
}

vg_rislive_t *vg_rislive_start(const vg_rislive_opts_t *opts,
                               vg_event_sink_fn sink, void *user) {
    struct vg_rislive *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->opts = *opts;
    c->sink = sink;
    c->user = user;
    c->linebuf = malloc(LINE_MAX_LEN);
    if (!c->linebuf) {
        free(c);
        return NULL;
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
    if (pthread_create(&c->thread, NULL, run, c) != 0) {
        free(c->linebuf);
        free(c);
        return NULL;
    }
    return c;
}

void vg_rislive_stats(vg_rislive_t *c, vg_rislive_stats_t *out) {
    out->messages = atomic_load(&c->messages);
    out->events = atomic_load(&c->events);
    out->parse_errors = atomic_load(&c->parse_errors);
    out->reconnects = atomic_load(&c->reconnects);
    out->connected = atomic_load(&c->connected);
}

void vg_rislive_stop(vg_rislive_t *c) {
    if (!c) return;
    atomic_store(&c->stop, true);
    pthread_join(c->thread, NULL);
    free(c->linebuf);
    free(c);
}
