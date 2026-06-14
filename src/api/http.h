/*
 * Minimal HTTP/1.1 server: one thread per connection, no keep-alive
 * pipelining, no chunked request bodies. Enough for a REST API and a
 * static dashboard — not a general-purpose web server.
 */
#ifndef VIGIL_HTTP_H
#define VIGIL_HTTP_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char        method[8];
    char        path[512];      /* decoded, query string stripped */
    char        query[512];     /* raw query string, "" if none */
} vg_http_req_t;

typedef struct {
    int         status;
    const char *content_type;
    char       *body;      /* heap-allocated; server frees it */
    size_t      body_len;
} vg_http_res_t;

typedef void (*vg_http_handler_fn)(const vg_http_req_t *req, vg_http_res_t *res,
                                   void *user);

typedef struct vg_http_server vg_http_server_t;

/* Routes are matched by exact path, or by prefix if the pattern ends
 * with a trailing slash-star wildcard. First match wins. */
vg_http_server_t *vg_http_server_new(int port);
int  vg_http_route(vg_http_server_t *s, const char *method, const char *pattern,
                   vg_http_handler_fn fn, void *user);
/* Starts the accept loop on a background thread. Returns 0 ok. */
int  vg_http_server_start(vg_http_server_t *s);
void vg_http_server_stop(vg_http_server_t *s);

/* Query-string helper: copies the value for `key` into out (URL-
 * decoded); returns true if present. */
bool vg_http_query_get(const char *query, const char *key, char *out, size_t n);

/* Path-parameter helper for prefix-matched routes: returns a pointer
 * into req->path just past the given prefix. */
const char *vg_http_path_tail(const char *path, const char *prefix);

#endif
