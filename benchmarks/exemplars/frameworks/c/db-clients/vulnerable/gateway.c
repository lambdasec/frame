/* Key/value gateway: a client sends a customer id over TCP; we answer from PostgreSQL or MySQL. */
#include <libpq-fe.h>
#include <mysql/mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static PGconn *pg;
static MYSQL *my;

void lookup_postgres(int fd) {
    char id[64];
    ssize_t got = recv(fd, id, sizeof(id) - 1, 0);
    if (got <= 0)
        return;
    id[got] = '\0';
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT name FROM customers WHERE id = '%s'", id);
    PGresult *res = PQexec(pg, sql); /* frame-expect: CWE-89 */
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0)
        dprintf(fd, "%s\n", PQgetvalue(res, 0, 0));
    PQclear(res);
}

void lookup_mysql(int fd) {
    char cid[64];
    ssize_t n = recv(fd, cid, sizeof(cid) - 1, 0);
    if (n <= 0)
        return;
    cid[n] = '\0';
    char query[256];
    sprintf(query, "SELECT name FROM customers WHERE id = '%s'", cid);
    mysql_query(my, query); /* frame-expect: CWE-89 */
    MYSQL_RES *rows = mysql_store_result(my);
    MYSQL_ROW row = mysql_fetch_row(rows);
    if (row)
        dprintf(fd, "%s\n", row[0]);
    mysql_free_result(rows);
}
