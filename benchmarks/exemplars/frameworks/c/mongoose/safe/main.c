/* Mongoose HTTP server: user lookup, thumbnail conversion, file download, greeting. */
#include "mongoose.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static sqlite3 *db;

/* Escape &, <, > and quotes for an HTML text node. */
static void mg_html_escape(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (; *in && o + 7 < cap; in++) {
        if (*in == '<')       o += snprintf(out + o, cap - o, "&lt;");
        else if (*in == '>')  o += snprintf(out + o, cap - o, "&gt;");
        else if (*in == '&')  o += snprintf(out + o, cap - o, "&amp;");
        else if (*in == '"')  o += snprintf(out + o, cap - o, "&quot;");
        else                  out[o++] = *in;
    }
    out[o] = '\0';
}

static void fn(struct mg_connection *c, int ev, void *ev_data) {
    if (ev != MG_EV_HTTP_MSG) return;
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;

    if (mg_http_match_uri(hm, "/api/user")) {
        char name[100], email[256] = "";
        sqlite3_stmt *stmt;
        mg_http_get_var(&hm->query, "name", name, sizeof(name));
        sqlite3_prepare_v2(db, "SELECT email FROM users WHERE name = ?", -1, &stmt, NULL);
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW)
            snprintf(email, sizeof(email), "%s", sqlite3_column_text(stmt, 0));
        sqlite3_finalize(stmt);
        mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "%s\n", email);
    } else if (mg_http_match_uri(hm, "/api/thumbnail")) {
        char *convert_args[] = {"convert", "-resize", "64x64", "upload.bin", "thumb.png", NULL};
        FILE *up = fopen("upload.bin", "wb");
        if (up) {
            fwrite(hm->body.buf, 1, hm->body.len, up);
            fclose(up);
        }
        execvp("convert", convert_args);
        mg_http_reply(c, 200, "", "done\n");
    } else if (mg_http_match_uri(hm, "/download")) {
        struct mg_http_serve_opts opts = {0};
        opts.root_dir = "/srv/files";   /* the library resolves the URI under root_dir and rejects ".." */
        mg_http_serve_dir(c, hm, &opts);
    } else if (mg_http_match_uri(hm, "/hello")) {
        char who[64], escaped[400];
        mg_http_get_var(&hm->query, "who", who, sizeof(who));
        mg_html_escape(who, escaped, sizeof(escaped));
        mg_http_reply(c, 200, "Content-Type: text/html\r\n", "<h1>Hello, %s</h1>", escaped);
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
