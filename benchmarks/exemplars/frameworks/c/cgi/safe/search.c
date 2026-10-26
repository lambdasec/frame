/* CGI search endpoint: the query string, headers and POST body come from the environment / stdin. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define MAX_BODY 4096

static void html_header(void) {
    printf("Content-Type: text/html\r\n\r\n");
}

static int print_row(void *unused, int argc, char **argv, char **cols) {
    (void)unused; (void)cols;
    for (int i = 0; i < argc; i++)
        printf("<td>%s</td>", argv[i] ? argv[i] : "");
    return 0;
}

static void lookup(sqlite3 *db, const char *name) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT id, email FROM users WHERE name = ?", -1, &stmt, NULL) != SQLITE_OK)
        return;
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(stmt) == SQLITE_ROW)
        printf("<td>%s</td>", sqlite3_column_text(stmt, 1));
    sqlite3_finalize(stmt);
}

static void search_by_query(sqlite3 *db) {
    char *name = getenv("QUERY_STRING");
    if (name)
        lookup(db, name);
}

static void search_by_body(sqlite3 *db) {
    char *len_s = getenv("CONTENT_LENGTH");
    int len = len_s ? atoi(len_s) : 0;
    char body[MAX_BODY];
    if (len <= 0 || len >= MAX_BODY)
        return;
    fread(body, 1, len, stdin);
    body[len] = '\0';
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "SELECT id, email FROM users WHERE name = ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, body, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

static void ping_host(void) {
    char *host = getenv("QUERY_STRING");
    /* only hosts we operate may be pinged; the argument vector never holds user text */
    if (host != NULL && strcmp(host, "db1.internal") == 0)
        execlp("ping", "ping", "-c", "1", "db1.internal", (char *)NULL);
    else if (host != NULL && strcmp(host, "cache1.internal") == 0)
        execlp("ping", "ping", "-c", "1", "cache1.internal", (char *)NULL);
}

static void log_agent(void) {
    char *agent = getenv("HTTP_USER_AGENT");
    printf("%s", agent ? agent : "");
}

int main(void) {
    sqlite3 *db;
    sqlite3_open("app.db", &db);
    html_header();
    search_by_query(db);
    search_by_body(db);
    ping_host();
    log_agent();
    sqlite3_close(db);
    return 0;
}
