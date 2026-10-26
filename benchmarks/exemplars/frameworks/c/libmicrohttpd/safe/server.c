/* A small page server on GNU libmicrohttpd: profile lookup, static files, upload hook. */
#include <microhttpd.h>
#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT 8080

static PGconn *db;

/* Escape the characters that are special in HTML text and attribute values. */
static void html_escape(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (; in && *in && o + 7 < cap; in++) {
        switch (*in) {
        case '<': o += snprintf(out + o, cap - o, "&lt;"); break;
        case '>': o += snprintf(out + o, cap - o, "&gt;"); break;
        case '&': o += snprintf(out + o, cap - o, "&amp;"); break;
        case '"': o += snprintf(out + o, cap - o, "&quot;"); break;
        default:  out[o++] = *in;
        }
    }
    out[o] = '\0';
}

static enum MHD_Result handle_profile(struct MHD_Connection *connection) {
    const char *user = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "user");
    char page[1024];
    char safe_user[256];
    const char *values[1] = { user };
    PGresult *res = PQexecParams(db, "SELECT bio FROM profiles WHERE name = $1",
                                 1, NULL, values, NULL, NULL, 0);
    html_escape(user, safe_user, sizeof(safe_user));
    snprintf(page, sizeof(page), "<html><body><h1>%s</h1><p>%s</p></body></html>",
             safe_user, PQgetvalue(res, 0, 0));
    PQclear(res);
    struct MHD_Response *response =
        MHD_create_response_from_buffer(strlen(page), page, MHD_RESPMEM_MUST_COPY);
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    return ret;
}

static enum MHD_Result handle_static(struct MHD_Connection *connection, const char *url) {
    /* only files from a fixed table are served; the path never contains request text */
    const char *path = NULL;
    if (strcmp(url, "/style.css") == 0)
        path = "/var/www/static/style.css";
    else if (strcmp(url, "/logo.png") == 0)
        path = "/var/www/static/logo.png";
    if (!path)
        return MHD_NO;
    FILE *f = fopen(path, "rb");
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
        FILE *log = fopen("/var/log/uploads.log", "a");
        if (log) {
            fwrite(upload_data, 1, *upload_data_size, log);
            fclose(log);
        }
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
