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

static void search_by_query(sqlite3 *db) {
    char *name = getenv("QUERY_STRING");
    char sql[512];
    snprintf(sql, sizeof(sql), "SELECT id, email FROM users WHERE name = '%s'", name);
    sqlite3_exec(db, sql, print_row, NULL, NULL); /* frame-expect: CWE-89 */
}

static void search_by_body(sqlite3 *db) {
    char *len_s = getenv("CONTENT_LENGTH");
    int len = len_s ? atoi(len_s) : 0;
    char body[MAX_BODY];
    char sql[MAX_BODY + 64];
    if (len <= 0 || len >= MAX_BODY)
        return;
    fread(body, 1, len, stdin);
    body[len] = '\0';
    sprintf(sql, "SELECT id, email FROM users WHERE name = '%s'", body);
    sqlite3_exec(db, sql, print_row, NULL, NULL); /* frame-expect: CWE-89 */
}

static void ping_host(void) {
    char *host = getenv("QUERY_STRING");
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    system(cmd); /* frame-expect: CWE-78 */
}

static void log_agent(void) {
    char *agent = getenv("HTTP_USER_AGENT");
    printf(agent); /* frame-expect: CWE-134 */
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
