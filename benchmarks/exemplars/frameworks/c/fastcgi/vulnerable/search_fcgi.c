/* FastCGI product search: parameters come from the web server through FCGX_GetParam. */
#include <fcgiapp.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sqlite3 *db;

static void search(FCGX_Request *req) {
    const char *term = FCGX_GetParam("QUERY_STRING", req->envp);
    char sql[512];
    snprintf(sql, sizeof(sql), "SELECT name, price FROM products WHERE name LIKE '%%%s%%'", term);
    sqlite3_exec(db, sql, NULL, NULL, NULL); /* frame-expect: CWE-89 */
    FCGX_PutS("Content-Type: text/html\r\n\r\n", req->out);
    FCGX_PutS(term, req->out); /* frame-expect: CWE-79 */
}

static void download(FCGX_Request *req) {
    const char *name = FCGX_GetParam("PATH_INFO", req->envp);
    char path[256];
    snprintf(path, sizeof(path), "/srv/downloads%s", name);
    FILE *f = fopen(path, "rb"); /* frame-expect: CWE-22 */
    if (f)
        fclose(f);
}

static void greet(FCGX_Request *req) {
    char body[256];
    int n = FCGX_GetStr(body, sizeof(body) - 1, req->in);
    body[n] = '\0';
    FCGX_FPrintF(req->out, body); /* frame-expect: CWE-134 */
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
