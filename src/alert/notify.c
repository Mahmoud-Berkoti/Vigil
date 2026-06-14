#include "notify.h"

#include "../core/log.h"

#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QUEUE_CAP 256

struct vg_notifier {
    char       url[512];
    pthread_t  thread;
    bool       running;
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    vg_alert_t queue[QUEUE_CAP];
    int        head, tail, count;
    bool       stop;
};

/* minimal JSON string escaping into out (bounded) */
static void jesc(const char *in, char *out, size_t n) {
    size_t w = 0;
    for (const char *c = in; *c && w + 2 < n; c++) {
        if (*c == '"' || *c == '\\') {
            out[w++] = '\\';
            out[w++] = *c;
        } else if ((unsigned char)*c < 0x20) {
            if (w + 6 >= n) break;
            w += (size_t)snprintf(out + w, n - w, "\\u%04x", *c);
        } else {
            out[w++] = *c;
        }
    }
    out[w] = '\0';
}

int vg_alert_to_json(const vg_alert_t *a, char *buf, size_t n) {
    char pfx[VG_PREFIX_STRLEN] = "";
    if (a->prefix.family != 0) vg_prefix_format(&a->prefix, pfx, sizeof(pfx));
    char summary[2 * VG_ALERT_SUMMARY_LEN], peer[2 * VG_PEER_STRLEN];
    jesc(a->summary, summary, sizeof(summary));
    jesc(a->peer, peer, sizeof(peer));
    /* evidence is JSON we produced ourselves: embed as-is when it looks
     * like an object, else as null */
    const char *ev = a->evidence[0] == '{' ? a->evidence : "null";
    int w = snprintf(buf, n,
                     "{\"id\":%lld,\"timestamp\":%.3f,\"type\":\"%s\","
                     "\"severity\":\"%s\",\"prefix\":\"%s\","
                     "\"expected_asn\":%u,\"observed_asn\":%u,"
                     "\"peer\":\"%s\",\"summary\":\"%s\",\"evidence\":%s}",
                     (long long)a->id, a->timestamp, vg_alert_type_str(a->type),
                     vg_severity_str(a->severity), pfx, a->expected_asn,
                     a->observed_asn, peer, summary, ev);
    return w < 0 || (size_t)w >= n ? (int)n - 1 : w;
}

static size_t discard(char *p, size_t sz, size_t nm, void *u) {
    (void)p;
    (void)u;
    return sz * nm;
}

static void post_webhook(const char *url, const vg_alert_t *a) {
    char body[2048];
    vg_alert_to_json(a, body, sizeof(body));

    CURL *h = curl_easy_init();
    if (!h) return;
    struct curl_slist *hdrs =
        curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(h, CURLOPT_URL, url);
    curl_easy_setopt(h, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, discard);
    CURLcode rc = curl_easy_perform(h);
    if (rc != CURLE_OK)
        vg_log(VG_LOG_WARN, "notify", "webhook failed: %s",
               curl_easy_strerror(rc));
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(h);
}

static void *run(void *arg) {
    vg_notifier_t *n = arg;
    for (;;) {
        pthread_mutex_lock(&n->mu);
        while (n->count == 0 && !n->stop) pthread_cond_wait(&n->cv, &n->mu);
        if (n->count == 0 && n->stop) {
            pthread_mutex_unlock(&n->mu);
            return NULL;
        }
        vg_alert_t a = n->queue[n->head];
        n->head = (n->head + 1) % QUEUE_CAP;
        n->count--;
        pthread_mutex_unlock(&n->mu);
        post_webhook(n->url, &a);
    }
}

vg_notifier_t *vg_notifier_start(const char *webhook_url) {
    vg_notifier_t *n = calloc(1, sizeof(*n));
    if (!n) return NULL;
    snprintf(n->url, sizeof(n->url), "%s", webhook_url ? webhook_url : "");
    pthread_mutex_init(&n->mu, NULL);
    pthread_cond_init(&n->cv, NULL);
    if (n->url[0]) {
        if (pthread_create(&n->thread, NULL, run, n) != 0) {
            free(n);
            return NULL;
        }
        n->running = true;
    }
    return n;
}

void vg_notifier_send(vg_notifier_t *n, const vg_alert_t *a) {
    /* structured log always */
    char pfx[VG_PREFIX_STRLEN] = "-";
    if (a->prefix.family != 0) vg_prefix_format(&a->prefix, pfx, sizeof(pfx));
    vg_log(a->severity == VG_SEV_CRITICAL ? VG_LOG_ERROR : VG_LOG_WARN,
           "alert", "[%s/%s] %s prefix=%s peer=%s",
           vg_alert_type_str(a->type), vg_severity_str(a->severity),
           a->summary, pfx, a->peer);

    if (!n->running) return;
    pthread_mutex_lock(&n->mu);
    if (n->count < QUEUE_CAP) {
        n->queue[n->tail] = *a;
        n->tail = (n->tail + 1) % QUEUE_CAP;
        n->count++;
        pthread_cond_signal(&n->cv);
    } /* full queue: drop rather than block ingest */
    pthread_mutex_unlock(&n->mu);
}

void vg_notifier_stop(vg_notifier_t *n) {
    if (!n) return;
    if (n->running) {
        pthread_mutex_lock(&n->mu);
        n->stop = true;
        pthread_cond_signal(&n->cv);
        pthread_mutex_unlock(&n->mu);
        pthread_join(n->thread, NULL);
    }
    pthread_mutex_destroy(&n->mu);
    pthread_cond_destroy(&n->cv);
    free(n);
}
