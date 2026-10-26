/* A small page server on GNU libmicrohttpd: profile lookup, static files, upload hook. */
#include <microhttpd.h>
#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT 8080

static PGconn *db;

static enum MHD_Result handle_profile(struct MHD_Connection *connection) {
    const char *user = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "user");
    char query[512];
    char page[1024];
    snprintf(query, sizeof(query), "SELECT bio FROM profiles WHERE name = '%s'", user);
    PGresult *res = PQexec(db, query); /* frame-expect: CWE-89 */
    snprintf(page, sizeof(page), "<html><body><h1>%s</h1><p>%s</p></body></html>",
             user, PQgetvalue(res, 0, 0));
    PQclear(res);
    struct MHD_Response *response = MHD_create_response_from_buffer( /* frame-expect: CWE-79 */
        strlen(page), page, MHD_RESPMEM_MUST_COPY);
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

static enum MHD_Result handle_static(struct MHD_Connection *connection, const char *url) {
    char path[512];
    snprintf(path, sizeof(path), "/var/www/static%s", url);
    FILE *f = fopen(path, "rb"); /* frame-expect: CWE-22 */
    if (!f)
        return MHD_NO;
    fclose(f);
    return MHD_YES;
}

static enum MHD_Result answer_to_connection(void *cls, struct MHD_Connection *connection,
                                            const char *url, const char *method,
                                            const char *version, const char *upload_data,
                                            size_t *upload_data_size, void **con_cls)
{
    if (strcmp(url, "/profile") == 0)
        return handle_profile(connection);

    if (strcmp(method, "POST") == 0 && *upload_data_size > 0) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "logger -t upload '%s'", upload_data);
        system(cmd); /* frame-expect: CWE-78 */
        *upload_data_size = 0;
        return MHD_YES;
    }
    return handle_static(connection, url);
}

int main(void) {
    db = PQconnectdb("dbname=app");
    struct MHD_Daemon *d = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL,
                                            &answer_to_connection, NULL, MHD_OPTION_END);
    getchar();
    MHD_stop_daemon(d);
    return 0;
}
