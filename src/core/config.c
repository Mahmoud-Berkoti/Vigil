#include "config.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vg_config_defaults(vg_config_t *c) {
    memset(c, 0, sizeof(*c));
    c->api_port = 8080;
    c->replay_speed = 0;
    snprintf(c->alert_db, sizeof(c->alert_db), "vigil.db");
    c->baseline_window = 300;
    c->spike_window = 60;
    c->spike_factor = 10;
    c->spike_min = 20;
}

static void trim(char *s) {
    char *start = s;
    while (*start == ' ' || *start == '\t') start++;
    size_t len = strlen(start);
    while (len > 0 && (start[len - 1] == ' ' || start[len - 1] == '\t' ||
                       start[len - 1] == '\n' || start[len - 1] == '\r'))
        start[--len] = '\0';
    memmove(s, start, len + 1);
}

static bool parse_bool(const char *v) {
    return strcmp(v, "true") == 0 || strcmp(v, "1") == 0 || strcmp(v, "yes") == 0;
}

int vg_config_load(vg_config_t *c, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        vg_log(VG_LOG_ERROR, "config", "cannot open %s", path);
        return -1;
    }
    char line[1024];
    int lineno = 0, rc = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        trim(line);
        if (line[0] == '\0') continue;

        char *eq = strchr(line, '=');
        if (!eq) {
            vg_log(VG_LOG_ERROR, "config", "%s:%d: expected key=value", path, lineno);
            rc = -1;
            break;
        }
        *eq = '\0';
        char *key = line, *val = eq + 1;
        trim(key);
        trim(val);

        if (strcmp(key, "api_port") == 0) {
            c->api_port = atoi(val);
        } else if (strcmp(key, "mrt_file") == 0) {
            snprintf(c->mrt_file, sizeof(c->mrt_file), "%.*s",
                    (int)sizeof(c->mrt_file) - 1, val);
        } else if (strcmp(key, "replay_speed") == 0) {
            c->replay_speed = atof(val);
        } else if (strcmp(key, "rislive_enabled") == 0) {
            c->rislive_enabled = parse_bool(val);
        } else if (strcmp(key, "rislive_host") == 0) {
            snprintf(c->rislive_host, sizeof(c->rislive_host), "%.*s",
                    (int)sizeof(c->rislive_host) - 1, val);
        } else if (strcmp(key, "rislive_prefix") == 0) {
            snprintf(c->rislive_prefix, sizeof(c->rislive_prefix), "%.*s",
                    (int)sizeof(c->rislive_prefix) - 1, val);
        } else if (strcmp(key, "vrp_file") == 0) {
            snprintf(c->vrp_file, sizeof(c->vrp_file), "%.*s",
                    (int)sizeof(c->vrp_file) - 1, val);
        } else if (strcmp(key, "alert_db") == 0) {
            snprintf(c->alert_db, sizeof(c->alert_db), "%.*s",
                    (int)sizeof(c->alert_db) - 1, val);
        } else if (strcmp(key, "webhook_url") == 0) {
            snprintf(c->webhook_url, sizeof(c->webhook_url), "%.*s",
                    (int)sizeof(c->webhook_url) - 1, val);
        } else if (strcmp(key, "baseline_window") == 0) {
            c->baseline_window = atof(val);
        } else if (strcmp(key, "spike_window") == 0) {
            c->spike_window = atof(val);
        } else if (strcmp(key, "spike_factor") == 0) {
            c->spike_factor = atof(val);
        } else if (strcmp(key, "spike_min") == 0) {
            c->spike_min = atoi(val);
        } else if (strcmp(key, "rel_provider") == 0) {
            /* "rel_provider = 3356 64500": AS3356 is AS64500's provider */
            unsigned long p2 = 0, c2 = 0;
            if (sscanf(val, "%lu %lu", &p2, &c2) != 2 || c->n_rels >= VG_MAX_RELS) {
                vg_log(VG_LOG_ERROR, "config", "%s:%d: bad rel_provider '%s'",
                       path, lineno, val);
                rc = -1;
                break;
            }
            c->rel_provider[c->n_rels] = (uint32_t)p2;
            c->rel_customer[c->n_rels] = (uint32_t)c2;
            c->n_rels++;
        } else if (strcmp(key, "rel_peer") == 0) {
            unsigned long a = 0, b = 0;
            if (sscanf(val, "%lu %lu", &a, &b) != 2 ||
                c->n_peer_rels >= VG_MAX_RELS) {
                vg_log(VG_LOG_ERROR, "config", "%s:%d: bad rel_peer '%s'",
                       path, lineno, val);
                rc = -1;
                break;
            }
            c->peer_a[c->n_peer_rels] = (uint32_t)a;
            c->peer_b[c->n_peer_rels] = (uint32_t)b;
            c->n_peer_rels++;
        } else if (strcmp(key, "watch") == 0) {
            /* "watch = 192.0.2.0/24 64500" or "watch = 192.0.2.0/24" */
            if (c->n_watch >= VG_MAX_WATCH) {
                vg_log(VG_LOG_ERROR, "config", "%s:%d: too many watch entries", path, lineno);
                rc = -1;
                break;
            }
            char pfx[VG_PREFIX_STRLEN];
            unsigned long asn = 0;
            int n = sscanf(val, "%63s %lu", pfx, &asn);
            if (n < 1 || vg_prefix_parse(pfx, &c->watch_prefix[c->n_watch]) != 0) {
                vg_log(VG_LOG_ERROR, "config", "%s:%d: bad watch prefix '%s'", path, lineno, val);
                rc = -1;
                break;
            }
            c->watch_origin[c->n_watch] = (uint32_t)asn;
            c->n_watch++;
        } else {
            vg_log(VG_LOG_ERROR, "config", "%s:%d: unknown key '%s'", path, lineno, key);
            rc = -1;
            break;
        }
    }
    fclose(f);
    return rc;
}
