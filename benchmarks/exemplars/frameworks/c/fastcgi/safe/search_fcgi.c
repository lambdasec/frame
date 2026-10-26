/* FastCGI product search: parameters come from the web server through FCGX_GetParam. */
#include <fcgiapp.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sqlite3 *db;

/* HTML-escape `in` into `out` (at most cap bytes, NUL included). */
static void html_escape(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (; in && *in && o + 7 < cap; in++) {
        if (*in == '<')      o += snprintf(out + o, cap - o, "&lt;");
        else if (*in == '>') o += snprintf(out + o, cap - o, "&gt;");
        else if (*in == '&') o += snprintf(out + o, cap - o, "&amp;");
        else if (*in == '"') o += snprintf(out + o, cap - o, "&quot;");
        else                 out[o++] = *in;
    }
    out[o] = '\0';
}

static void search(FCGX_Request *req) {
    const char *term = FCGX_GetParam("QUERY_STRING", req->envp);
    char pattern[256], escaped[1024];
    snprintf(pattern, sizeof(pattern), "%%%s%%", term);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT name, price FROM products WHERE name LIKE ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    html_escape(term, escaped, sizeof(escaped));
    FCGX_PutS("Content-Type: text/html\r\n\r\n", req->out);
    FCGX_PutS(escaped, req->out);
}

static void download(FCGX_Request *req) {
    const char *name = FCGX_GetParam("PATH_INFO", req->envp);
    const char *path = NULL;
    if (strcmp(name, "/manual.pdf") == 0)
        path = "/srv/downloads/manual.pdf";
    else if (strcmp(name, "/price-list.csv") == 0)
        path = "/srv/downloads/price-list.csv";
    if (!path)
        return;
    FILE *f = fopen(path, "rb");
    if (f)
        fclose(f);
}

static void greet(FCGX_Request *req) {
    char body[256];
    int n = FCGX_GetStr(body, sizeof(body) - 1, req->in);
    body[n] = '\0';
    FCGX_FPrintF(req->out, "%s", body);
}

int main(void) {
    FCGX_Request req;
    sqlite3_open("shop.db", &db);
    FCGX_Init();
    FCGX_InitRequest(&req, 0, 0);
    while (FCGX_Accept_r(&req) == 0) {
        search(&req);
        download(&req);
        greet(&req);
        FCGX_Finish_r(&req);
    }
    return 0;
}
