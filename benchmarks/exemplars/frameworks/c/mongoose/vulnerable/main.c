/* Mongoose HTTP server: user lookup, thumbnail conversion, file download, greeting. */
#include "mongoose.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sqlite3 *db;

static int collect(void *out, int argc, char **argv, char **cols) {
    (void) argc; (void) cols;
    snprintf((char *) out, 256, "%s", argv[0] ? argv[0] : "");
    return 0;
}

static void fn(struct mg_connection *c, int ev, void *ev_data) {
    if (ev != MG_EV_HTTP_MSG) return;
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;

    if (mg_http_match_uri(hm, "/api/user")) {
        char name[100], sql[256], email[256] = "";
        mg_http_get_var(&hm->query, "name", name, sizeof(name));
        snprintf(sql, sizeof(sql), "SELECT email FROM users WHERE name = '%s'", name);
        sqlite3_exec(db, sql, collect, email, NULL); /* frame-expect: CWE-89 */
        mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "%s\n", email);
    } else if (mg_http_match_uri(hm, "/api/thumbnail")) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "convert -resize 64x64 %.*s thumb.png", (int) hm->body.len, hm->body.buf);
        system(cmd); /* frame-expect: CWE-78 */
        mg_http_reply(c, 200, "", "done\n");
    } else if (mg_http_match_uri(hm, "/download")) {
        char file[128], path[256];
        mg_http_get_var(&hm->query, "file", file, sizeof(file));
        snprintf(path, sizeof(path), "/srv/files/%s", file);
        struct mg_http_serve_opts opts = {0};
        mg_http_serve_file(c, hm, path, &opts); /* frame-expect: CWE-22 */
    } else if (mg_http_match_uri(hm, "/hello")) {
        char who[64];
        mg_http_get_var(&hm->query, "who", who, sizeof(who));
        mg_http_reply(c, 200, "Content-Type: text/html\r\n", "<h1>Hello, %s</h1>", who); /* reflected XSS: not reported yet, see the pack note */
    } else {
        mg_http_reply(c, 404, "", "not found\n");
    }
}

int main(void) {
    struct mg_mgr mgr;
    sqlite3_open("users.db", &db);
    mg_mgr_init(&mgr);
    mg_http_listen(&mgr, "http://0.0.0.0:8000", fn, NULL);
    for (;;) mg_mgr_poll(&mgr, 1000);
    mg_mgr_free(&mgr);
    return 0;
}
