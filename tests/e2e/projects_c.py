"""Realistic C/C++ projects: each case is a vulnerable tree and its safe twin.

Marked lines (`// frame-expect: CWE-n`) are where the report must point. A file is written once, with
the lines that differ between the two trees as a fork:

    @@<<
    vulnerable lines            (carry the frame-expect marker)
    @@==
    the fix a developer would make
    @@>>

so the safe twin differs ONLY by the fix. C/C++ have no cross-file taint, so every flow stays inside
one translation unit; multi-file cases ship headers and several `.c` files that are analysed
independently (a defect in one file must not leak into, or be hidden by, its neighbours).
Source is written one statement per line, like real code: several analyzers are line based.

Realistic flows Frame cannot follow yet live in test_known_gaps_cnative.py, not here.
"""

import re

CASES = {}

_FORK = re.compile(r"^@@<<\n(.*?)^@@==\n(.*?)^@@>>\n", re.S | re.M)


def _tree(files, which):
    return {path: _FORK.sub(lambda m: m.group(which), text) for path, text in files.items()}


def case(name, files):
    """Register a case: `files` maps path -> text with `@@<< ... @@== ... @@>>` forks."""
    for text in files.values():
        assert text.count("@@<<") == text.count("@@==") == text.count("@@>>"), name
    CASES[name] = (_tree(files, 1), _tree(files, 2))


# --------------------------------------------------------------------------------------
# Command injection
case("cgi_getenv_system", {
    "cgi/search.c": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CMD_MAX 512

static int log_search(const char *term)
{
@@<<
    char cmd[CMD_MAX];
    snprintf(cmd, sizeof(cmd), "grep -c '%s' /var/log/app/access.log", term);
    return system(cmd);  // frame-expect: CWE-78
@@==
    char *args[] = {"grep", "-c", "-F", "--", (char *)term, "/var/log/app/access.log", NULL};
    pid_t pid = fork();
    if (pid == 0) {
        execvp("grep", args);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return status;
@@>>
}

int main(void)
{
    const char *query = getenv("QUERY_STRING");
    if (query == NULL) {
        puts("Status: 400 Bad Request\r\n\r\n");
        return 1;
    }
    puts("Content-Type: text/plain\r\n\r\n");
    return log_search(query);
}
''',
})

case("argv_popen_ping", {
    "tools/netcheck.c": r'''#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void report(const char *host)
{
@@<<
    char line[256];
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    FILE *fp = popen(cmd, "r");  // frame-expect: CWE-78
    if (fp == NULL) {
        perror("popen");
        return;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        fputs(line, stdout);
    }
    pclose(fp);
@@==
    char *args[] = {"ping", "-c", "1", "--", (char *)host, NULL};
    execvp("ping", args);
    perror("execvp");
@@>>
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s host\n", argv[0]);
        return 2;
    }
    report(argv[1]);
    return 0;
}
''',
})

case("cpp_std_system_getenv", {
    "src/backup.cpp": r'''#include <cstdlib>
#include <spawn.h>
#include <string>

extern char **environ;

int run_backup()
{
    const char *target = std::getenv("BACKUP_TARGET");
    if (target == nullptr) {
        return 1;
    }
@@<<
    std::string cmd = "tar czf /backups/out.tgz ";
    cmd += target;
    return std::system(cmd.c_str());  // frame-expect: CWE-78
@@==
    char *argv[] = {(char *)"tar", (char *)"czf", (char *)"/backups/out.tgz", (char *)"--", (char *)target, nullptr};
    pid_t pid;
    return posix_spawnp(&pid, "tar", nullptr, nullptr, argv, environ);
@@>>
}
''',
})

# --------------------------------------------------------------------------------------
# SQL injection
case("sqlite_exec_cgi", {
    "web/notes.c": r'''#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

static int print_row(void *unused, int ncol, char **vals, char **names)
{
    for (int i = 0; i < ncol; i++) {
        printf("%s=%s\n", names[i], vals[i] ? vals[i] : "NULL");
    }
    return 0;
}

int main(void)
{
    sqlite3 *db;
    if (sqlite3_open("notes.db", &db) != SQLITE_OK) {
        return 1;
    }
    const char *owner = getenv("REMOTE_USER");
    if (owner == NULL) {
        owner = "guest";
    }
@@<<
    char sql[512];
    char *err = NULL;
    snprintf(sql, sizeof(sql), "SELECT id, body FROM notes WHERE owner = '%s'", owner);
    int rc = sqlite3_exec(db, sql, print_row, NULL, &err);  // frame-expect: CWE-89
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sql: %s\n", err);
        sqlite3_free(err);
    }
@@==
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, "SELECT id, body FROM notes WHERE owner = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sql: %s\n", sqlite3_errmsg(db));
        return rc;
    }
    sqlite3_bind_text(stmt, 1, owner, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        printf("id=%d body=%s\n", sqlite3_column_int(stmt, 0), sqlite3_column_text(stmt, 1));
    }
    sqlite3_finalize(stmt);
@@>>
    sqlite3_close(db);
    return rc;
}
''',
})

# --------------------------------------------------------------------------------------
# Buffer overflows from network input
case("recv_strcpy_session", {
    "srv/session.c": r'''#include <string.h>
#include <sys/socket.h>
#include <stdio.h>

struct session {
    char user[32];
    int authed;
};

static void handle_login(int fd, struct session *s)
{
    char packet[512];
    ssize_t n = recv(fd, packet, sizeof(packet) - 1, 0);
    if (n <= 0) {
        return;
    }
    packet[n] = '\0';
@@<<
    strcpy(s->user, packet);  // frame-expect: CWE-120
@@==
    strncpy(s->user, packet, sizeof(s->user) - 1);
    s->user[sizeof(s->user) - 1] = '\0';
@@>>
    s->authed = 0;
}

int serve(int fd)
{
    struct session s;
    handle_login(fd, &s);
    printf("login from %s\n", s.user);
    return 0;
}
''',
})

case("stdin_gets_scanf_name", {
    "cli/greet.c": r'''#include <stdio.h>
#include <string.h>

int main(void)
{
    char name[32];
    printf("name? ");
@@<<
    scanf("%s", name);  // frame-expect: CWE-120
@@==
    if (fgets(name, sizeof(name), stdin) == NULL) {
        return 1;
    }
    name[strcspn(name, "\n")] = '\0';
@@>>
    printf("hello, %s\n", name);
    return 0;
}
''',
})

case("tainted_index_stats_table", {
    "net/stats.c": r'''#include <stdint.h>
#include <sys/socket.h>

#define NUM_OPS 8

int tally(int fd)
{
    int per_op[NUM_OPS] = {0};
    uint8_t msg[16];
    if (recv(fd, msg, sizeof(msg), 0) < 1) {
        return -1;
    }
    int op = msg[0];
@@<<
    per_op[op] += 1;  // frame-expect: CWE-787
@@==
    if (op >= NUM_OPS) {
        return -1;
    }
    per_op[op] += 1;
@@>>
    return per_op[0];
}
''',
})

case("loop_off_by_one_copy", {
    "util/fill.c": r'''#include <string.h>

#define SLOTS 32

void fill_slots(const unsigned char *src)
{
    unsigned char slots[SLOTS];
@@<<
    for (int i = 0; i <= SLOTS; i++) {
        slots[i] = src[i];  // frame-expect: CWE-787
    }
@@==
    for (int i = 0; i < SLOTS; i++) {
        slots[i] = src[i];
    }
@@>>
    memcpy(slots, src, 4);
}
''',
})

# --------------------------------------------------------------------------------------
# Format strings
case("syslog_user_format", {
    "log/logger.c": r'''#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

void log_client_line(int fd)
{
    char line[200];
    ssize_t n = read(fd, line, sizeof(line) - 1);
    if (n <= 0) {
        return;
    }
    line[n] = '\0';
@@<<
    syslog(LOG_INFO, line);  // frame-expect: CWE-134
@@==
    syslog(LOG_INFO, "%s", line);
@@>>
}
''',
})

case("printf_argv_format", {
    "cli/main.c": r'''#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: tool <file>\n");
        return 2;
    }
@@<<
    printf(argv[1]);  // frame-expect: CWE-134
@@==
    printf("%s", argv[1]);
@@>>
    printf("\n");
    return 0;
}
''',
})

# --------------------------------------------------------------------------------------
# Integer overflow in allocation
case("malloc_count_times_size", {
    "img/decode.c": r'''#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_COLORS 65536

struct pixel {
    uint8_t r, g, b, a;
};

struct pixel *read_palette(int fd)
{
    uint32_t count;
    if (read(fd, &count, sizeof(count)) != sizeof(count)) {
        return NULL;
    }
@@<<
    struct pixel *pal = malloc(count * sizeof(struct pixel));  // frame-expect: CWE-190
@@==
    if (count == 0 || count > MAX_COLORS) {
        return NULL;
    }
    struct pixel *pal = calloc(count, sizeof(struct pixel));
@@>>
    if (pal == NULL) {
        return NULL;
    }
    if (read(fd, pal, count * sizeof(struct pixel)) < 0) {
        free(pal);
        return NULL;
    }
    return pal;
}
''',
})

# --------------------------------------------------------------------------------------
# Memory lifecycle in realistic data structures
case("list_remove_use_after_free", {
    "ds/list.c": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct node {
    char *name;
    struct node *next;
};

struct node *push(struct node *head, const char *name)
{
    struct node *n = malloc(sizeof(*n));
    if (n == NULL) {
        return head;
    }
    n->name = strdup(name);
    n->next = head;
    return n;
}

struct node *drop_first(struct node *head)
{
    struct node *rest = head->next;
@@<<
    free(head->name);
    free(head);
    printf("dropped %s\n", head->name);  // frame-expect: CWE-416
@@==
    printf("dropped %s\n", head->name);
    free(head->name);
    free(head);
@@>>
    return rest;
}
''',
})

case("goto_cleanup_double_free", {
    "util/config_load.c": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct config {
    char *path;
    char *data;
};

int config_load(struct config *cfg, const char *path)
{
    int rc = -1;
    FILE *fp = NULL;
    char *buf = malloc(4096);
    if (buf == NULL) {
        return -1;
    }
    fp = fopen(path, "r");
    if (fp == NULL) {
        goto out;
    }
    size_t n = fread(buf, 1, 4095, fp);
    buf[n] = '\0';
    cfg->data = strdup(buf);
    cfg->path = strdup(path);
    rc = 0;
@@<<
    free(buf);
@@==
@@>>
out:
    if (fp != NULL) {
        fclose(fp);
    }
    free(buf);  // frame-expect: CWE-415
    return rc;
}
''',
})

case("unchecked_malloc_null_deref", {
    "ds/buffer_pool.c": r'''#include <stdlib.h>
#include <string.h>

struct slot {
    unsigned char *data;
    size_t cap;
    int in_use;
};

struct slot *slot_new(size_t cap)
{
@@<<
    struct slot *s = malloc(sizeof(*s));  // frame-expect: CWE-252
    s->cap = cap;
@@==
    struct slot *s = malloc(sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    s->cap = cap;
@@>>
    s->in_use = 0;
    s->data = NULL;
    return s;
}
''',
})

case("parse_early_return_leak", {
    "parse/header.c": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct header {
    char *key;
    char *value;
};

int parse_header(const char *line, struct header *out)
{
    char *copy = strdup(line);  // frame-expect: CWE-401
    if (copy == NULL) {
        return -1;
    }
    char *colon = strchr(copy, ':');
@@<<
    if (colon == NULL) {
        return -1;
    }
@@==
    if (colon == NULL) {
        goto fail;
    }
@@>>
    *colon = '\0';
    out->key = strdup(copy);
    out->value = strdup(colon + 1);
    free(copy);
    return 0;
@@<<
@@==
fail:
    free(copy);
    return -1;
@@>>
}
''',
})

case("uninitialised_status_read", {
    "svc/status.c": r'''enum { OK = 0, DEGRADED = 1, DOWN = 2 };

int overall_status(int free_mb, int load)
{
@@<<
    int status;
@@==
    int status = OK;
@@>>
    if (free_mb < 100) {
        status = DOWN;
    } else if (load > 90) {
        status = DEGRADED;
    }
    return status;  // frame-expect: CWE-457
}
''',
})

case("return_stack_buffer", {
    "util/names.c": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

@@<<
char *make_label(int id)
{
    char label[32];
    snprintf(label, sizeof(label), "item-%d", id);
    return label;  // frame-expect: CWE-562
}
@@==
char *make_label(int id)
{
    char *label = malloc(32);
    if (label == NULL) {
        return NULL;
    }
    snprintf(label, 32, "item-%d", id);
    return label;
}
@@>>
''',
})

case("cpp_new_delete_leak", {
    "src/registry.cpp": r'''#include <map>
#include <string>

struct Plugin {
    std::string name;
    explicit Plugin(const std::string &n) : name(n) {}
};

static std::map<std::string, Plugin *> g_plugins;

bool register_plugin(const std::string &name)
{
    Plugin *p = new Plugin(name);  // frame-expect: CWE-401
    if (g_plugins.count(name) != 0) {
@@<<
@@==
        delete p;
@@>>
        return false;
    }
    g_plugins[name] = p;
    return true;
}
''',
})

case("cpp_array_new_scalar_delete", {
    "src/scratch.cpp": r'''#include <cstddef>
#include <cstring>

std::size_t checksum(const unsigned char *src, std::size_t n)
{
    unsigned char *copy = new unsigned char[n];
    std::memcpy(copy, src, n);
    std::size_t sum = 0;
    for (std::size_t i = 0; i < n; i++) {
        sum += copy[i];
    }
@@<<
    delete copy;  // frame-expect: CWE-762
@@==
    delete[] copy;
@@>>
    return sum;
}
''',
})

# --------------------------------------------------------------------------------------
# Files and temp files
case("fopen_download_traversal", {
    "http/static.c": r'''#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DOC_ROOT "/srv/www/files"

int main(void)
{
    const char *request_path = getenv("PATH_INFO");
    if (request_path == NULL) {
        request_path = "index.html";
    }
    char full[PATH_MAX];
    snprintf(full, sizeof(full), "%s/%s", DOC_ROOT, request_path);
@@<<
    FILE *fp = fopen(full, "rb");  // frame-expect: CWE-22
@@==
    char resolved[PATH_MAX];
    if (realpath(full, resolved) == NULL || strncmp(resolved, DOC_ROOT "/", strlen(DOC_ROOT) + 1) != 0) {
        puts("Status: 403 Forbidden\r\n\r\n");
        return 1;
    }
    FILE *fp = fopen(resolved, "rb");
@@>>
    if (fp == NULL) {
        puts("Status: 404 Not Found\r\n\r\n");
        return 1;
    }
    char chunk[1024];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        fwrite(chunk, 1, n, stdout);
    }
    fclose(fp);
    return 0;
}
''',
})

case("mktemp_race", {
    "util/spool.c": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int spool_write(const char *data)
{
    char name[] = "/tmp/spoolXXXXXX";
@@<<
    mktemp(name);  // frame-expect: CWE-377
    FILE *fp = fopen(name, "w");
    if (fp == NULL) {
        return -1;
    }
@@==
    int fd = mkstemp(name);
    if (fd < 0) {
        return -1;
    }
    FILE *fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        return -1;
    }
@@>>
    fputs(data, fp);
    fclose(fp);
    return 0;
}
''',
})

case("access_open_toctou", {
    "util/safe_open.c": r'''#include <fcntl.h>
#include <unistd.h>

int open_for_user(const char *path)
{
@@<<
    if (access(path, W_OK) != 0) {
        return -1;
    }
    return open(path, O_WRONLY | O_APPEND);  // frame-expect: CWE-367
@@==
    return open(path, O_WRONLY | O_APPEND | O_NOFOLLOW);
@@>>
}
''',
})

# --------------------------------------------------------------------------------------
# Crypto and secrets
case("md5_password_hash", {
    "auth/hash.c": r'''@@<<
#include <openssl/md5.h>
@@==
#include <openssl/sha.h>
@@>>
#include <stdio.h>
#include <string.h>

@@<<
void hash_password(const char *password, char out[33])
{
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char *)password, strlen(password), digest);  // frame-expect: CWE-328
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
@@==
void hash_password(const char *password, char out[65])
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)password, strlen(password), digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
@@>>
        sprintf(out + i * 2, "%02x", digest[i]);
    }
}
''',
})

case("rand_session_token", {
    "auth/token.c": r'''#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
@@<<
@@==
#include <openssl/rand.h>
@@>>

void new_session_token(char out[65])
{
    unsigned char raw[16];
    unsigned char digest[SHA256_DIGEST_LENGTH];
@@<<
    srand((unsigned)time(NULL));
    for (int i = 0; i < 16; i++) {
        raw[i] = (unsigned char)rand();
    }
@@==
    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        out[0] = '\0';
        return;
    }
@@>>
    SHA256(raw, sizeof(raw), digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(out + i * 2, "%02x", digest[i]);  // frame-expect: CWE-338
    }
}
''',
})

case("hardcoded_db_password", {
    "db/connect.c": r'''#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>

PGconn *db_connect(void)
{
@@<<
    const char *password = "Sup3rS3cret!2024";  // frame-expect: CWE-259
@@==
    const char *password = getenv("APP_DB_PASSWORD");
    if (password == NULL) {
        return NULL;
    }
@@>>
    char conninfo[256];
    snprintf(conninfo, sizeof(conninfo), "host=db.internal dbname=app user=app password=%s", password);
    return PQconnectdb(conninfo);
}
''',
})

# --------------------------------------------------------------------------------------
# Library packs (C and C++)
case("libxml2_entity_expansion", {
    "import/orders.c": r'''#include <libxml/parser.h>
#include <sys/socket.h>

int load_order(int client)
{
    static char doc_buf[65536];
    ssize_t len = recv(client, doc_buf, sizeof(doc_buf), 0);
    if (len <= 0) {
        return -1;
    }
@@<<
    xmlDocPtr doc = xmlReadMemory(doc_buf, (int)len, "order.xml", NULL, XML_PARSE_NOENT | XML_PARSE_DTDLOAD);  // frame-expect: CWE-611
@@==
    xmlDocPtr doc = xmlReadMemory(doc_buf, (int)len, "order.xml", NULL, XML_PARSE_NONET | XML_PARSE_NOBLANKS);
@@>>
    if (doc == NULL) {
        return -1;
    }
    xmlFreeDoc(doc);
    return 0;
}
''',
})

case("curl_relay_ssrf", {
    "relay/fetch.c": r'''#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

void relay(int client)
{
    char req[512];
    ssize_t n = recv(client, req, sizeof(req) - 1, 0);
    if (n <= 0) {
        return;
    }
    req[n] = '\0';
@@<<
    char *url = req;
@@==
    int id = atoi(req);
    char url[600];
    snprintf(url, sizeof(url), "https://api.partner.example/items/%d", id);
@@>>
    CURL *curl = curl_easy_init();
@@<<
    curl_easy_setopt(curl, CURLOPT_URL, url);  // frame-expect: CWE-918
@@==
    curl_easy_setopt(curl, CURLOPT_URL, url);
@@>>
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}
''',
})

case("qt_sql_and_process", {
    "src/admin.cpp": r'''#include <QProcess>
#include <QSqlQuery>
#include <QTcpSocket>

void handle_lookup(QTcpSocket *sock)
{
    QString name = QString::fromUtf8(sock->readLine()).trimmed();
    QSqlQuery query;
@@<<
    query.exec("SELECT email FROM users WHERE name = '" + name + "'");  // frame-expect: CWE-89
@@==
    query.prepare("SELECT email FROM users WHERE name = ?");
    query.addBindValue(name);
    query.exec();
@@>>
    if (query.next()) {
        sock->write(query.value(0).toString().toUtf8());
    }
}

void handle_ping(QTcpSocket *sock)
{
    QString host = QString::fromUtf8(sock->readLine()).trimmed();
    QProcess proc;
@@<<
    proc.start("sh", QStringList() << "-c" << "ping -c 1 " + host);  // frame-expect: CWE-78
@@==
    proc.start("ping", QStringList() << "-c" << "1" << "--" << "127.0.0.1");
@@>>
    proc.waitForFinished();
    sock->write(proc.readAllStandardOutput());
}
''',
})

case("httplib_report_handlers", {
    "src/server.cpp": r'''#include "httplib.h"
#include <cstdlib>
#include <string>

int main()
{
    httplib::Server svr;
    svr.Get("/report", [](const httplib::Request &req, httplib::Response &res) {
        std::string fmt = req.get_param_value("format");
@@<<
        std::string cmd = "report-gen --format " + fmt;
        std::system(cmd.c_str());  // frame-expect: CWE-78
@@==
        if (fmt != "pdf" && fmt != "csv") {
            res.status = 400;
            return;
        }
        std::system("report-gen --format pdf");
@@>>
        res.set_content("queued", "text/plain");
    });
    svr.listen("0.0.0.0", 8080);
    return 0;
}
''',
})

# --------------------------------------------------------------------------------------
# A multi-file project: headers plus several translation units, each analysed on its own.
case("project_with_headers_independent_units", {
    "include/store.h": r'''#ifndef STORE_H
#define STORE_H

#include <sqlite3.h>

int store_open(sqlite3 **db, const char *path);
int store_lookup_current_user(sqlite3 *db);
void store_close(sqlite3 *db);

#endif
''',
    "include/util.h": r'''#ifndef UTIL_H
#define UTIL_H

void trim(char *s);
int parse_port(const char *s);

#endif
''',
    "src/util.c": r'''#include "util.h"
#include <stdlib.h>
#include <string.h>

void trim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == ' ')) {
        s[--n] = '\0';
    }
}

int parse_port(const char *s)
{
    long v = strtol(s, NULL, 10);
    if (v < 1 || v > 65535) {
        return -1;
    }
    return (int)v;
}
''',
    "src/store.c": r'''#include "store.h"
#include <stdio.h>
#include <stdlib.h>

int store_open(sqlite3 **db, const char *path)
{
    return sqlite3_open(path, db);
}

int store_lookup_current_user(sqlite3 *db)
{
    const char *owner = getenv("REMOTE_USER");
    if (owner == NULL) {
        return -1;
    }
@@<<
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT body FROM notes WHERE owner = '%s'", owner);
    return sqlite3_exec(db, sql, NULL, NULL, NULL);  // frame-expect: CWE-89
@@==
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT body FROM notes WHERE owner = ?", -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, owner, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc;
@@>>
}

void store_close(sqlite3 *db)
{
    sqlite3_close(db);
}
''',
    "src/main.c": r'''#include "store.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    sqlite3 *db;
    if (argc < 2) {
        fprintf(stderr, "usage: %s <db>\n", argv[0]);
        return 2;
    }
    if (store_open(&db, argv[1]) != 0) {
        return 1;
    }
    store_lookup_current_user(db);
    store_close(db);
    return 0;
}
''',
})


# A constant allowlist checked with strcmp before the value reaches the shell.
case("strcmp_allowlist_before_system", {
    "cgi/level.c": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const char *term = getenv("QUERY_STRING");
    char cmd[256];
@@<<
    if (term == NULL) {
        return 1;
    }
@@==
    if (term == NULL || (strcmp(term, "error") != 0 && strcmp(term, "warn") != 0)) {
        return 1;
    }
@@>>
    snprintf(cmd, sizeof(cmd), "grep -c %s /var/log/app.log", term);
    return system(cmd);  // frame-expect: CWE-78
}
''',
})

# A character-set check (strspn over letters, digits, dot, hyphen) before popen.
case("strspn_charset_before_popen", {
    "cgi/ping.c": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    const char *host = getenv("TARGET_HOST");
    char cmd[256];
@@<<
    if (host == NULL) {
        return 1;
    }
@@==
    if (host == NULL || strspn(host, "abcdefghijklmnopqrstuvwxyz0123456789.-") != strlen(host)) {
        return 1;
    }
@@>>
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    FILE *fp = popen(cmd, "r");  // frame-expect: CWE-78
    if (fp != NULL) {
        pclose(fp);
    }
    return 0;
}
''',
})

# A key looked up in a table of literals: the command uses the table's value, never the key.
case("map_allowlist_before_std_system", {
    "src/backup.cpp": r'''#include <cstdlib>
#include <map>
#include <string>

int run_backup()
{
    const char *target = std::getenv("BACKUP_TARGET");
    if (target == nullptr) {
        return 1;
    }
    static const std::map<std::string, std::string> kTargets = {{"home", "/home"}, {"etc", "/etc"}};
    auto it = kTargets.find(target);
    if (it == kTargets.end()) {
        return 2;
    }
@@<<
    std::string cmd = std::string("tar czf /backups/out.tgz ") + target;
@@==
    std::string cmd = "tar czf /backups/out.tgz " + it->second;
@@>>
    return std::system(cmd.c_str());  // frame-expect: CWE-78
}
''',
})

# A URL that must start with a fixed scheme://host/ prefix (strncmp) before curl fetches it.
case("prefix_allowlist_before_curl", {
    "src/relay.c": r'''#include <curl/curl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define ALLOWED "https://api.partner.example/"

void relay(int client)
{
    char url[512];
    ssize_t n = recv(client, url, sizeof(url) - 1, 0);
    if (n <= 0) {
        return;
    }
    url[n] = '\0';
@@<<
@@==
    if (strncmp(url, ALLOWED, strlen(ALLOWED)) != 0) {
        return;
    }
@@>>
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);  // frame-expect: CWE-918
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}
''',
})

# A number parsed with atoi before it is formatted into the URL.
case("nested_atoi_in_snprintf_argument", {
    "src/items.c": r'''#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

void relay(int client)
{
    char req[512];
    ssize_t n = recv(client, req, sizeof(req) - 1, 0);
    if (n <= 0) {
        return;
    }
    req[n] = '\0';
    char url[600];
@@<<
    snprintf(url, sizeof(url), "%s", req);
@@==
    snprintf(url, sizeof(url), "https://api.partner.example/items/%d", atoi(req));
@@>>
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);  // frame-expect: CWE-918
    curl_easy_perform(curl);
}
''',
})

# A length read from the wire, checked against the destination's capacity before memcpy.
case("memcpy_length_checked_against_capacity", {
    "src/msg.c": r'''#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define MAX_BODY 256

struct msg {
    uint8_t body[MAX_BODY];
    uint16_t len;
};

int read_msg(int fd, struct msg *out)
{
    uint8_t hdr[2];
    uint8_t payload[4096];
    if (read(fd, hdr, 2) != 2) {
        return -1;
    }
    uint16_t len = (uint16_t)((hdr[0] << 8) | hdr[1]);
    if (read(fd, payload, sizeof(payload)) < 0) {
        return -1;
    }
@@<<
@@==
    if (len > MAX_BODY) {
        return -1;
    }
@@>>
    memcpy(out->body, payload, len);  // frame-expect: CWE-120
    out->len = len;
    return 0;
}
''',
})

# Attacker data passed into a helper function that builds and runs the SQL (C interprocedural taint).
case("helper_gets_tainted_sql", {
    "cgi/notes.c": r'''#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

static int find_notes(sqlite3 *db, const char *owner)
{
    char sql[512];
    snprintf(sql, sizeof(sql), "SELECT body FROM notes WHERE owner = '%s'", owner);
    return sqlite3_exec(db, sql, NULL, NULL, NULL);  // frame-expect: CWE-89
}

int main(void)
{
    sqlite3 *db;
    if (sqlite3_open("notes.db", &db) != SQLITE_OK) {
        return 1;
    }
@@<<
    const char *owner = getenv("REMOTE_USER");
@@==
    const char *owner = "anonymous";
@@>>
    return find_notes(db, owner);
}
''',
})

# Attacker data passed into a helper that opens a file under a fixed directory.
case("helper_gets_tainted_path", {
    "cgi/files.c": r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

static int serve(const char *name)
{
    char full[512];
    snprintf(full, sizeof(full), "/srv/files/%s", name);
    FILE *fp = fopen(full, "r");  // frame-expect: CWE-22
    if (fp == NULL) {
        return 404;
    }
    fclose(fp);
    return 200;
}

int main(void)
{
@@<<
    const char *p = getenv("PATH_INFO");
@@==
    const char *p = "index.html";
@@>>
    return serve(p);
}
''',
})

# Attacker text formatted with an unbounded %s into a smaller stack buffer.
case("sprintf_untrusted_into_small_buffer", {
    "src/banner.c": r'''#include <stdio.h>
#include <string.h>
#include <unistd.h>

void send_banner(int fd)
{
    char banner[64];
    char name[256];
    ssize_t n = read(fd, name, sizeof(name) - 1);
    if (n <= 0) {
        return;
    }
    name[n] = '\0';
@@<<
    sprintf(banner, "hello %s\n", name);  // frame-expect: CWE-120
@@==
    snprintf(banner, sizeof(banner), "hello %s\n", name);
@@>>
    write(fd, banner, strlen(banner));
}
''',
})

# A byte from the network indexes a file-scope table.
case("tainted_index_into_global_table", {
    "src/tally.c": r'''#include <stdint.h>
#include <sys/socket.h>

#define NUM_OPS 8

static int per_op[NUM_OPS];

int tally(int fd)
{
    uint8_t msg[16];
    if (recv(fd, msg, sizeof(msg), 0) < 1) {
        return -1;
    }
    int op = msg[0];
@@<<
@@==
    if (op < 0 || op >= NUM_OPS) {
        return -1;
    }
@@>>
    per_op[op] += 1;  // frame-expect: CWE-787
    return per_op[0];
}
''',
})

# A buffer freed on an error branch that returns, and freed again only on the other path.
case("free_in_branch_then_free_on_other_path", {
    "src/header.c": r'''#include <stdlib.h>
#include <string.h>

int parse_header(const char *line)
{
    char *copy = strdup(line);
    if (copy == NULL) {
        return -1;
    }
    char *colon = strchr(copy, ':');
    if (colon == NULL) {
        free(copy);
@@<<
@@==
        return -1;
@@>>
    }
    *colon = '\0';
    free(copy);  // frame-expect: CWE-415
    return 0;
}
''',
})

# A member allocated with new[] in the constructor's initializer list and released by the destructor.
case("member_array_new_scalar_delete", {
    "src/framebuffer.cpp": r'''#include <cstddef>

class FrameBuffer {
public:
    explicit FrameBuffer(std::size_t n) : data_(new unsigned char[n]), size_(n) {}
@@<<
    ~FrameBuffer() { delete data_; }  // frame-expect: CWE-762
@@==
    ~FrameBuffer() { delete[] data_; }
@@>>
    std::size_t size() const { return size_; }

private:
    unsigned char *data_;
    std::size_t size_;
};
''',
})

# A loop that rejects the value at the first character that is not alphanumeric.
case("isalnum_loop_before_system", {
    "src/job.c": r'''#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

int run(void)
{
    const char *job = getenv("JOB_NAME");
    char cmd[256];
    if (job == NULL) {
        return -1;
    }
@@<<
@@==
    for (const char *p = job; *p; p++) {
        if (!isalnum((unsigned char)*p)) {
            return -1;
        }
    }
@@>>
    snprintf(cmd, sizeof(cmd), "run-job %s", job);
    return system(cmd);  // frame-expect: CWE-78
}
''',
})

# A session token built from rand() in a helper and set as a cookie by the caller (CWE-338).
case("rand_for_session_token", {
    "cgi/session.c": r'''#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <time.h>

static void new_session_token(char *out, size_t len)
{
@@<<
    srand((unsigned)time(NULL));
    for (size_t i = 0; i + 1 < len; i++) {
        out[i] = "0123456789abcdef"[rand() % 16];  // frame-expect: CWE-338
    }
@@==
    unsigned char bytes[64];
    getrandom(bytes, len, 0);
    for (size_t i = 0; i + 1 < len; i++) {
        out[i] = "0123456789abcdef"[bytes[i] % 16];
    }
@@>>
    out[len - 1] = '\0';
}

int main(void)
{
    char sid[33];
    new_session_token(sid, sizeof(sid));
    printf("Set-Cookie: session=%s; HttpOnly\r\n", sid);  // frame-expect: CWE-338
    printf("Content-Type: text/plain\r\n\r\nok\n");
    return 0;
}
''',
})
