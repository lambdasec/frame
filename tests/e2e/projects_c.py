"""Realistic C/C++ projects: each case is a vulnerable tree and its safe twin.

Marked lines (`// frame-expect: CWE-n`) are where the report must point; the safe twin differs
only by the fix a developer would make. C/C++ have no cross-file taint, so every flow stays
inside one translation unit; multi-file cases ship headers and several `.c` files that are
analysed independently (a defect in one file must not leak into, or be hidden by, its neighbours).
Source is written one statement per line, like real code.
"""

CASES = {}


def case(name, vulnerable, safe):
    CASES[name] = (vulnerable, safe)


def twin(name, files, *edits):
    """A case whose safe twin is the vulnerable tree with `edits` ((path, old, new)) applied.

    The marker comments are dropped from the twin so it reads as ordinary code.
    """
    safe = dict(files)
    for path, old, new in edits:
        assert old in safe[path], (name, path, old)
        safe[path] = safe[path].replace(old, new)
    for path, text in safe.items():
        safe[path] = "\n".join(line.split("  // frame-expect")[0] for line in text.split("\n"))
    case(name, files, safe)


# --------------------------------------------------------------------------------------
# Command injection
twin("cgi_getenv_system", {
    "cgi/search.c": '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CMD_MAX 512

static int log_search(const char *term)
{
    char cmd[CMD_MAX];
    snprintf(cmd, sizeof(cmd), "grep -c '%s' /var/log/app/access.log", term);
    return system(cmd);  // frame-expect: CWE-78
}

int main(void)
{
    const char *query = getenv("QUERY_STRING");
    if (query == NULL) {
        puts("Status: 400 Bad Request\\r\\n\\r\\n");
        return 1;
    }
    puts("Content-Type: text/plain\\r\\n\\r\\n");
    return log_search(query);
}
''',
}, ("cgi/search.c", '''    snprintf(cmd, sizeof(cmd), "grep -c '%s' /var/log/app/access.log", term);
    return system(cmd);  // frame-expect: CWE-78''', '''    if (strcmp(term, "error") != 0 && strcmp(term, "warn") != 0) {
        return -1;
    }
    snprintf(cmd, sizeof(cmd), "grep -c '%s' /var/log/app/access.log", term);
    return system(cmd);'''))

twin("argv_popen_ping", {
    "tools/netcheck.c": '''#include <stdio.h>
#include <stdlib.h>

static void report(const char *host)
{
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
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s host\\n", argv[0]);
        return 2;
    }
    report(argv[1]);
    return 0;
}
''',
}, ("tools/netcheck.c", '''    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    FILE *fp = popen(cmd, "r");  // frame-expect: CWE-78''', '''    if (strspn(host, "abcdefghijklmnopqrstuvwxyz0123456789.-") != strlen(host)) {
        fprintf(stderr, "bad host\\n");
        return;
    }
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    FILE *fp = popen(cmd, "r");'''),
   ("tools/netcheck.c", "#include <stdlib.h>\n", "#include <stdlib.h>\n#include <string.h>\n"))

# --------------------------------------------------------------------------------------
# SQL injection
twin("sqlite_exec_cgi", {
    "web/notes.c": '''#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

static int print_row(void *unused, int ncol, char **vals, char **names)
{
    for (int i = 0; i < ncol; i++) {
        printf("%s=%s\\n", names[i], vals[i] ? vals[i] : "NULL");
    }
    return 0;
}

int find_notes(sqlite3 *db, const char *owner)
{
    char sql[512];
    char *err = NULL;
    snprintf(sql, sizeof(sql), "SELECT id, body FROM notes WHERE owner = '%s'", owner);
    int rc = sqlite3_exec(db, sql, print_row, NULL, &err);  // frame-expect: CWE-89
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sql: %s\\n", err);
        sqlite3_free(err);
    }
    return rc;
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
    find_notes(db, owner);
    sqlite3_close(db);
    return 0;
}
''',
}, ("web/notes.c", '''    char sql[512];
    char *err = NULL;
    snprintf(sql, sizeof(sql), "SELECT id, body FROM notes WHERE owner = '%s'", owner);
    int rc = sqlite3_exec(db, sql, print_row, NULL, &err);  // frame-expect: CWE-89
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sql: %s\\n", err);
        sqlite3_free(err);
    }
    return rc;''', '''    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, "SELECT id, body FROM notes WHERE owner = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sql: %s\\n", sqlite3_errmsg(db));
        return rc;
    }
    sqlite3_bind_text(stmt, 1, owner, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        printf("id=%d body=%s\\n", sqlite3_column_int(stmt, 0), sqlite3_column_text(stmt, 1));
    }
    sqlite3_finalize(stmt);
    return SQLITE_OK;'''))

# --------------------------------------------------------------------------------------
# Buffer overflows from network input
twin("recv_strcpy_session", {
    "srv/session.c": '''#include <string.h>
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
    packet[n] = '\\0';
    strcpy(s->user, packet);  // frame-expect: CWE-120
    s->authed = 0;
}

int serve(int fd)
{
    struct session s;
    handle_login(fd, &s);
    printf("login from %s\\n", s.user);
    return 0;
}
''',
}, ("srv/session.c", "    strcpy(s->user, packet);  // frame-expect: CWE-120", '''    strncpy(s->user, packet, sizeof(s->user) - 1);
    s->user[sizeof(s->user) - 1] = '\\0';'''))

twin("read_memcpy_length_prefix", {
    "proto/frame.c": '''#include <stdint.h>
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
    memcpy(out->body, payload, len);  // frame-expect: CWE-787
    out->len = len;
    return 0;
}
''',
}, ("proto/frame.c", '''    memcpy(out->body, payload, len);  // frame-expect: CWE-787''', '''    if (len > MAX_BODY) {
        return -1;
    }
    memcpy(out->body, payload, len);'''))

twin("sprintf_banner", {
    "net/banner.c": '''#include <stdio.h>
#include <string.h>
#include <unistd.h>

void send_banner(int fd)
{
    char host[128];
    char banner[64];
    if (gethostname(host, sizeof(host)) != 0) {
        return;
    }
    char name[256];
    ssize_t n = read(fd, name, sizeof(name) - 1);
    if (n <= 0) {
        return;
    }
    name[n] = '\\0';
    sprintf(banner, "hello %s from %s\\n", name, host);  // frame-expect: CWE-120
    write(fd, banner, strlen(banner));
}
''',
}, ("net/banner.c", '    sprintf(banner, "hello %s from %s\\n", name, host);  // frame-expect: CWE-120',
    '    snprintf(banner, sizeof(banner), "hello %s from %s\\n", name, host);'))

# --------------------------------------------------------------------------------------
# Format strings
twin("printf_user_format", {
    "log/logger.c": '''#include <stdio.h>
#include <syslog.h>
#include <unistd.h>

void log_client_line(int fd)
{
    char line[200];
    ssize_t n = read(fd, line, sizeof(line) - 1);
    if (n <= 0) {
        return;
    }
    line[n] = '\\0';
    syslog(LOG_INFO, line);  // frame-expect: CWE-134
}
''',
}, ("log/logger.c", "    syslog(LOG_INFO, line);  // frame-expect: CWE-134", '    syslog(LOG_INFO, "%s", line);'))

twin("fprintf_argv_usage", {
    "cli/main.c": '''#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: tool <file>\\n");
        return 2;
    }
    printf(argv[1]);  // frame-expect: CWE-134
    printf("\\n");
    return 0;
}
''',
}, ("cli/main.c", "    printf(argv[1]);  // frame-expect: CWE-134", '    printf("%s", argv[1]);'))

# --------------------------------------------------------------------------------------
# Integer overflow in allocation
twin("malloc_count_times_size", {
    "img/decode.c": '''#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct pixel {
    uint8_t r, g, b, a;
};

struct pixel *read_palette(int fd)
{
    uint32_t count;
    if (read(fd, &count, sizeof(count)) != sizeof(count)) {
        return NULL;
    }
    struct pixel *pal = malloc(count * sizeof(struct pixel));  // frame-expect: CWE-190
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
}, ("img/decode.c", '''    struct pixel *pal = malloc(count * sizeof(struct pixel));  // frame-expect: CWE-190''', '''    if (count == 0 || count > (1u << 20)) {
        return NULL;
    }
    struct pixel *pal = calloc(count, sizeof(struct pixel));'''))

# --------------------------------------------------------------------------------------
# Memory lifecycle in realistic data structures
twin("list_remove_use_after_free", {
    "ds/list.c": '''#include <stdio.h>
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
    free(head->name);
    free(head);
    printf("dropped %s\\n", head->name);  // frame-expect: CWE-416
    return rest;
}
''',
}, ("ds/list.c", '''    free(head->name);
    free(head);
    printf("dropped %s\\n", head->name);  // frame-expect: CWE-416''', '''    printf("dropped %s\\n", head->name);
    free(head->name);
    free(head);'''))

twin("goto_cleanup_double_free", {
    "util/config_load.c": '''#include <stdio.h>
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
    buf[n] = '\\0';
    cfg->data = buf;
    cfg->path = strdup(path);
    rc = 0;
    free(buf);  // frame-expect: CWE-415
out:
    if (fp != NULL) {
        fclose(fp);
    }
    free(buf);
    return rc;
}
''',
}, ("util/config_load.c", '''    cfg->data = buf;
    cfg->path = strdup(path);
    rc = 0;
    free(buf);  // frame-expect: CWE-415''', '''    cfg->data = buf;
    buf = NULL;
    cfg->path = strdup(path);
    rc = 0;'''))

twin("unchecked_malloc_null_deref", {
    "ds/buffer_pool.c": '''#include <stdlib.h>
#include <string.h>

#define POOL_SLOTS 16

struct slot {
    unsigned char *data;
    size_t cap;
    int in_use;
};

static struct slot pool[POOL_SLOTS];

struct slot *pool_acquire(size_t cap)
{
    for (int i = 0; i < POOL_SLOTS; i++) {
        if (!pool[i].in_use) {
            pool[i].data = malloc(cap);
            memset(pool[i].data, 0, cap);  // frame-expect: CWE-476
            pool[i].cap = cap;
            pool[i].in_use = 1;
            return &pool[i];
        }
    }
    return NULL;
}
''',
}, ("ds/buffer_pool.c", '''            pool[i].data = malloc(cap);
            memset(pool[i].data, 0, cap);  // frame-expect: CWE-476''', '''            pool[i].data = malloc(cap);
            if (pool[i].data == NULL) {
                return NULL;
            }
            memset(pool[i].data, 0, cap);'''))

twin("parse_early_return_leak", {
    "parse/header.c": '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct header {
    char *key;
    char *value;
};

int parse_header(const char *line, struct header *out)
{
    char *copy = strdup(line);
    if (copy == NULL) {
        return -1;
    }
    char *colon = strchr(copy, ':');
    if (colon == NULL) {
        return -1;  // frame-expect: CWE-401
    }
    *colon = '\\0';
    out->key = strdup(copy);
    out->value = strdup(colon + 1);
    free(copy);
    return 0;
}
''',
}, ("parse/header.c", '''    if (colon == NULL) {
        return -1;  // frame-expect: CWE-401
    }''', '''    if (colon == NULL) {
        free(copy);
        return -1;
    }'''))

twin("uninitialised_status_read", {
    "svc/status.c": '''#include <stdio.h>

enum { OK = 0, DEGRADED = 1, DOWN = 2 };

int check_disk(int free_mb);

int overall_status(int free_mb, int load)
{
    int status;
    if (free_mb < 100) {
        status = DOWN;
    } else if (load > 90) {
        status = DEGRADED;
    }
    printf("status=%d\\n", status);  // frame-expect: CWE-457
    return status;
}
''',
}, ("svc/status.c", '''    int status;
    if (free_mb < 100) {''', '''    int status = OK;
    if (free_mb < 100) {'''))

# --------------------------------------------------------------------------------------
# Files and temp files
twin("fopen_download_traversal", {
    "http/static.c": '''#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DOC_ROOT "/srv/www/files"

int serve_file(const char *request_path, FILE *out)
{
    char full[PATH_MAX];
    snprintf(full, sizeof(full), "%s/%s", DOC_ROOT, request_path);
    FILE *fp = fopen(full, "rb");  // frame-expect: CWE-22
    if (fp == NULL) {
        return 404;
    }
    char chunk[1024];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        fwrite(chunk, 1, n, out);
    }
    fclose(fp);
    return 200;
}

int main(void)
{
    const char *p = getenv("PATH_INFO");
    return serve_file(p ? p : "index.html", stdout) == 200 ? 0 : 1;
}
''',
}, ("http/static.c", '''    FILE *fp = fopen(full, "rb");  // frame-expect: CWE-22''', '''    char resolved[PATH_MAX];
    if (realpath(full, resolved) == NULL || strncmp(resolved, DOC_ROOT "/", strlen(DOC_ROOT) + 1) != 0) {
        return 403;
    }
    FILE *fp = fopen(resolved, "rb");'''))

twin("mktemp_race", {
    "util/spool.c": '''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int spool_write(const char *data)
{
    char name[] = "/tmp/spoolXXXXXX";
    mktemp(name);  // frame-expect: CWE-377
    FILE *fp = fopen(name, "w");
    if (fp == NULL) {
        return -1;
    }
    fputs(data, fp);
    fclose(fp);
    return 0;
}
''',
}, ("util/spool.c", '''    mktemp(name);  // frame-expect: CWE-377
    FILE *fp = fopen(name, "w");
    if (fp == NULL) {
        return -1;
    }''', '''    int fd = mkstemp(name);
    if (fd < 0) {
        return -1;
    }
    FILE *fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        return -1;
    }'''))

twin("access_open_toctou", {
    "util/safe_open.c": '''#include <fcntl.h>
#include <unistd.h>

int open_for_user(const char *path)
{
    if (access(path, W_OK) != 0) {  // frame-expect: CWE-367
        return -1;
    }
    return open(path, O_WRONLY | O_APPEND);
}
''',
}, ("util/safe_open.c", '''    if (access(path, W_OK) != 0) {  // frame-expect: CWE-367
        return -1;
    }
    return open(path, O_WRONLY | O_APPEND);''', '''    return open(path, O_WRONLY | O_APPEND | O_NOFOLLOW);'''))

# --------------------------------------------------------------------------------------
# Crypto and secrets
twin("md5_password_hash", {
    "auth/hash.c": '''#include <openssl/md5.h>
#include <stdio.h>
#include <string.h>

void hash_password(const char *password, char out[33])
{
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char *)password, strlen(password), digest);  // frame-expect: CWE-327
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(out + i * 2, "%02x", digest[i]);
    }
}
''',
}, ("auth/hash.c", '#include <openssl/md5.h>', '#include <openssl/sha.h>'),
   ("auth/hash.c", '''    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char *)password, strlen(password), digest);  // frame-expect: CWE-327
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {''', '''    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)password, strlen(password), digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {'''),
   ("auth/hash.c", "char out[33]", "char out[65]"))

twin("rand_session_token", {
    "auth/token.c": '''#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void new_session_token(char *out, size_t len)
{
    srand((unsigned)time(NULL));
    for (size_t i = 0; i + 1 < len; i++) {
        out[i] = "0123456789abcdef"[rand() % 16];  // frame-expect: CWE-338
    }
    out[len - 1] = '\\0';
}
''',
}, ("auth/token.c", '''    srand((unsigned)time(NULL));
    for (size_t i = 0; i + 1 < len; i++) {
        out[i] = "0123456789abcdef"[rand() % 16];  // frame-expect: CWE-338
    }''', '''    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp == NULL) {
        return;
    }
    for (size_t i = 0; i + 1 < len; i++) {
        unsigned char b;
        if (fread(&b, 1, 1, fp) != 1) {
            break;
        }
        out[i] = "0123456789abcdef"[b % 16];
    }
    fclose(fp);'''))

twin("hardcoded_db_password", {
    "db/connect.c": '''#include <libpq-fe.h>
#include <stdio.h>
#include <stdlib.h>

PGconn *db_connect(void)
{
    const char *password = "Sup3rS3cret!2024";  // frame-expect: CWE-798
    char conninfo[256];
    snprintf(conninfo, sizeof(conninfo), "host=db.internal dbname=app user=app password=%s", password);
    return PQconnectdb(conninfo);
}
''',
}, ("db/connect.c", '''    const char *password = "Sup3rS3cret!2024";  // frame-expect: CWE-798''', '''    const char *password = getenv("APP_DB_PASSWORD");
    if (password == NULL) {
        return NULL;
    }'''))

# --------------------------------------------------------------------------------------
# C++
twin("cpp_new_delete_leak", {
    "src/registry.cpp": '''#include <map>
#include <string>

struct Plugin {
    std::string name;
    explicit Plugin(const std::string &n) : name(n) {}
};

static std::map<std::string, Plugin *> g_plugins;

bool register_plugin(const std::string &name)
{
    Plugin *p = new Plugin(name);
    if (g_plugins.count(name) != 0) {
        return false;  // frame-expect: CWE-401
    }
    g_plugins[name] = p;
    return true;
}
''',
}, ("src/registry.cpp", '''    if (g_plugins.count(name) != 0) {
        return false;  // frame-expect: CWE-401
    }''', '''    if (g_plugins.count(name) != 0) {
        delete p;
        return false;
    }'''))

twin("cpp_std_system_getenv", {
    "src/backup.cpp": '''#include <cstdlib>
#include <string>

int run_backup()
{
    const char *target = std::getenv("BACKUP_TARGET");
    if (target == nullptr) {
        return 1;
    }
    std::string cmd = "tar czf /backups/out.tgz ";
    cmd += target;
    return std::system(cmd.c_str());  // frame-expect: CWE-78
}
''',
}, ("src/backup.cpp", '''    std::string cmd = "tar czf /backups/out.tgz ";
    cmd += target;
    return std::system(cmd.c_str());  // frame-expect: CWE-78''', '''    std::string t(target);
    if (t.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_/") != std::string::npos) {
        return 2;
    }
    std::string cmd = "tar czf /backups/out.tgz ";
    cmd += t;
    return std::system(cmd.c_str());'''))
