#include "http.h"

#include "../core/log.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_ROUTES  64
#define MAX_HEADER  16384
#define MAX_BODY    (1 << 20)

typedef struct {
    char               method[8];
    char               pattern[256];
    bool               prefix_match;
    vg_http_handler_fn fn;
    void              *user;
} route_t;

struct vg_http_server {
    int        port;
    int        listen_fd;
    pthread_t  accept_thread;
    bool       running;
    route_t    routes[MAX_ROUTES];
    int        n_routes;
};

/* ---- URL decoding / query helpers ---------------------------------- */

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void url_decode(const char *in, char *out, size_t n) {
    size_t w = 0;
    for (const char *p = in; *p && w + 1 < n; p++) {
        if (*p == '%' && p[1] && p[2]) {
            int hi = hexval(p[1]), lo = hexval(p[2]);
            if (hi >= 0 && lo >= 0) {
                out[w++] = (char)((hi << 4) | lo);
                p += 2;
                continue;
            }
        }
        out[w++] = (*p == '+') ? ' ' : *p;
    }
    out[w] = '\0';
}

bool vg_http_query_get(const char *query, const char *key, char *out, size_t n) {
    size_t klen = strlen(key);
    const char *p = query;
    while (p && *p) {
        const char *eq = strchr(p, '=');
        const char *amp = strchr(p, '&');
        size_t seglen = amp ? (size_t)(amp - p) : strlen(p);
        if (eq && (size_t)(eq - p) == klen && strncmp(p, key, klen) == 0) {
            char raw[512];
            size_t vlen = seglen - (klen + 1);
            if (vlen >= sizeof(raw)) vlen = sizeof(raw) - 1;
            memcpy(raw, eq + 1, vlen);
            raw[vlen] = '\0';
            url_decode(raw, out, n);
            return true;
        }
        p = amp ? amp + 1 : NULL;
    }
    return false;
}

const char *vg_http_path_tail(const char *path, const char *prefix) {
    size_t n = strlen(prefix);
    if (strncmp(path, prefix, n) != 0) return NULL;
    return path + n;
}

/* ---- server --------------------------------------------------------- */

vg_http_server_t *vg_http_server_new(int port) {
    vg_http_server_t *s = calloc(1, sizeof(*s));
    if (s) s->port = port;
    return s;
}

int vg_http_route(vg_http_server_t *s, const char *method, const char *pattern,
                  vg_http_handler_fn fn, void *user) {
    if (s->n_routes >= MAX_ROUTES) return -1;
    route_t *r = &s->routes[s->n_routes++];
    snprintf(r->method, sizeof(r->method), "%s", method);
    size_t plen = strlen(pattern);
    r->prefix_match = plen >= 2 && pattern[plen - 1] == '*' && pattern[plen - 2] == '/';
    snprintf(r->pattern, sizeof(r->pattern), "%.*s", r->prefix_match ? (int)plen - 1 : (int)plen, pattern);
    r->fn = fn;
    r->user = user;
    return 0;
}

static const char *status_text(int code) {
    switch (code) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    default:  return "Error";
    }
}

/* Read one HTTP request off `fd`: request line + headers (bounded),
 * then the body per Content-Length (bounded). Returns 0 ok, -1 on
 * malformed/oversized/truncated input. */
static int read_request(int fd, vg_http_req_t *req, char **body, size_t *blen) {
    char buf[MAX_HEADER];
    size_t total = 0;
    ssize_t got;
    char *header_end = NULL;

    while (total < sizeof(buf) - 1) {
        got = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (got <= 0) return -1;
        total += (size_t)got;
        buf[total] = '\0';
        header_end = strstr(buf, "\r\n\r\n");
        if (header_end) break;
    }
    if (!header_end) return -1;
    size_t header_len = (size_t)(header_end - buf) + 4;

    /* request line */
    char method[8] = "", path_raw[1024] = "", proto[16] = "";
    if (sscanf(buf, "%7s %1023s %15s", method, path_raw, proto) != 3)
        return -1;
    snprintf(req->method, sizeof(req->method), "%s", method);

    char *qmark = strchr(path_raw, '?');
    if (qmark) {
        *qmark = '\0';
        snprintf(req->query, sizeof(req->query), "%s", qmark + 1);
    } else {
        req->query[0] = '\0';
    }
    char decoded[1024];
    url_decode(path_raw, decoded, sizeof(decoded));
    snprintf(req->path, sizeof(req->path), "%s", decoded);

    /* Content-Length (case-insensitive) */
    size_t content_len = 0;
    for (char *line = buf; line < header_end;) {
        char *nl = strstr(line, "\r\n");
        if (!nl || nl > header_end) break;
        if (strncasecmp(line, "Content-Length:", 15) == 0)
            content_len = (size_t)strtoul(line + 15, NULL, 10);
        line = nl + 2;
    }
    if (content_len > MAX_BODY) return -1;

    size_t have = total - header_len;
    char *b = malloc(content_len + 1);
    if (!b) return -1;
    if (have > content_len) have = content_len;
    memcpy(b, buf + header_len, have);
    while (have < content_len) {
        got = recv(fd, b + have, content_len - have, 0);
        if (got <= 0) {
            free(b);
            return -1;
        }
        have += (size_t)got;
    }
    b[content_len] = '\0';
    *body = b;
    *blen = content_len;
    return 0;
}

static void send_response(int fd, const vg_http_res_t *res) {
    char hdr[256];
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                     res->status, status_text(res->status),
                     res->content_type ? res->content_type : "text/plain",
                     res->body_len);
    if (send(fd, hdr, (size_t)n, 0) < 0) return;
    if (res->body_len) send(fd, res->body, res->body_len, 0);
}

typedef struct {
    vg_http_server_t *s;
    int                fd;
} conn_ctx_t;

static void *handle_conn(void *arg) {
    conn_ctx_t *cc = arg;
    vg_http_server_t *s = cc->s;
    int fd = cc->fd;
    free(cc);

    vg_http_req_t req;
    memset(&req, 0, sizeof(req));
    char *body = NULL;
    size_t blen = 0;

    vg_http_res_t res;
    memset(&res, 0, sizeof(res));
    res.content_type = "application/json";

    if (read_request(fd, &req, &body, &blen) != 0) {
        const char *msg = "{\"error\":\"bad request\"}";
        res.status = 400;
        res.body = strdup(msg);
        res.body_len = strlen(msg);
        send_response(fd, &res);
        free(res.body);
        free(body);
        close(fd);
        return NULL;
    }

    route_t *match = NULL;
    bool path_matched_other_method = false;
    for (int i = 0; i < s->n_routes; i++) {
        route_t *r = &s->routes[i];
        bool path_ok = r->prefix_match
            ? strncmp(req.path, r->pattern, strlen(r->pattern)) == 0
            : strcmp(req.path, r->pattern) == 0;
        if (!path_ok) continue;
        if (strcmp(r->method, req.method) == 0) {
            match = r;
            break;
        }
        path_matched_other_method = true;
    }

    if (match) {
        match->fn(&req, &res, match->user);
    } else {
        const char *msg = path_matched_other_method
            ? "{\"error\":\"method not allowed\"}"
            : "{\"error\":\"not found\"}";
        res.status = path_matched_other_method ? 405 : 404;
        res.body = strdup(msg);
        res.body_len = strlen(msg);
    }

    send_response(fd, &res);
    free(res.body);
    free(body);
    close(fd);
    return NULL;
}

static void *accept_loop(void *arg) {
    vg_http_server_t *s = arg;
    while (s->running) {
        struct sockaddr_in addr;
        socklen_t alen = sizeof(addr);
        int fd = accept(s->listen_fd, (struct sockaddr *)&addr, &alen);
        if (fd < 0) {
            if (s->running) vg_log(VG_LOG_WARN, "http", "accept failed");
            continue;
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        conn_ctx_t *cc = malloc(sizeof(*cc));
        cc->s = s;
        cc->fd = fd;
        pthread_t t;
        if (pthread_create(&t, NULL, handle_conn, cc) != 0) {
            close(fd);
            free(cc);
            continue;
        }
        pthread_detach(t);
    }
    return NULL;
}

int vg_http_server_start(vg_http_server_t *s) {
    s->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->listen_fd < 0) return -1;
    int one = 1;
    setsockopt(s->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)s->port);
    if (bind(s->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        vg_log(VG_LOG_ERROR, "http", "bind :%d failed", s->port);
        close(s->listen_fd);
        return -1;
    }
    if (listen(s->listen_fd, 64) != 0) {
        close(s->listen_fd);
        return -1;
    }
    s->running = true;
    if (pthread_create(&s->accept_thread, NULL, accept_loop, s) != 0) {
        s->running = false;
        close(s->listen_fd);
        return -1;
    }
    vg_log(VG_LOG_INFO, "http", "listening on :%d", s->port);
    return 0;
}

void vg_http_server_stop(vg_http_server_t *s) {
    if (!s || !s->running) return;
    s->running = false;
    shutdown(s->listen_fd, SHUT_RDWR);
    close(s->listen_fd);
    pthread_join(s->accept_thread, NULL);
}
