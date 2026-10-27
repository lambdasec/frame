"""Realistic C/C++ flows Frame does not follow yet (or reports wrongly), pinned so they cannot go unnoticed.

Each entry is a strict xfail: a MISS asserts the CWE is reported in the file, a FALSE POSITIVE asserts
it is not. The day the analysis learns the idiom the test XPASSes and fails the run until the entry is
moved into the regular matrix (`projects_c.py`).
"""

import pytest

from e2e_helpers import scan, write_tree

HDR = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n"

# (id, kind, cwe, source). kind: "miss" -> the CWE must be reported; "fp" -> it must not be.
GAPS = [
    # ---- C has no interprocedural taint: the request value is read in one function, used in another
    ("helper_gets_tainted_sql", "miss", "CWE-89", "t.c", '''#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

static int find_notes(sqlite3 *db, const char *owner)
{
    char sql[512];
    snprintf(sql, sizeof(sql), "SELECT body FROM notes WHERE owner = '%s'", owner);
    return sqlite3_exec(db, sql, NULL, NULL, NULL);
}

int main(void)
{
    sqlite3 *db;
    if (sqlite3_open("notes.db", &db) != SQLITE_OK) {
        return 1;
    }
    const char *owner = getenv("REMOTE_USER");
    return find_notes(db, owner);
}
'''),
    ("helper_gets_tainted_path", "miss", "CWE-22", "t.c", HDR + '''
static int serve(const char *name)
{
    char full[512];
    snprintf(full, sizeof(full), "/srv/files/%s", name);
    FILE *fp = fopen(full, "r");
    if (fp == NULL) {
        return 404;
    }
    fclose(fp);
    return 200;
}

int main(void)
{
    const char *p = getenv("PATH_INFO");
    return serve(p);
}
'''),
    # ---- validation idioms that make a value safe for a shell are not recognised
    ("strcmp_allowlist_before_system", "fp", "CWE-78", "t.c", HDR + '''
int run(void)
{
    const char *term = getenv("QUERY_STRING");
    char cmd[256];
    if (term == NULL || (strcmp(term, "error") != 0 && strcmp(term, "warn") != 0)) {
        return -1;
    }
    snprintf(cmd, sizeof(cmd), "grep -c %s /var/log/app.log", term);
    return system(cmd);
}
'''),
    ("strspn_charset_before_popen", "fp", "CWE-78", "t.c", HDR + '''
int run(const char *host_arg)
{
    const char *host = getenv("TARGET_HOST");
    char cmd[256];
    if (host == NULL || strspn(host, "abcdefghijklmnopqrstuvwxyz0123456789.-") != strlen(host)) {
        return -1;
    }
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
    FILE *fp = popen(cmd, "r");
    if (fp != NULL) {
        pclose(fp);
    }
    return 0;
}
'''),
    ("isalnum_loop_before_system", "fp", "CWE-78", "t.c", '''#include <ctype.h>
''' + HDR + '''
int run(void)
{
    const char *job = getenv("JOB_NAME");
    char cmd[256];
    if (job == NULL) {
        return -1;
    }
    for (const char *p = job; *p; p++) {
        if (!isalnum((unsigned char)*p)) {
            return -1;
        }
    }
    snprintf(cmd, sizeof(cmd), "run-job %s", job);
    return system(cmd);
}
'''),
    ("map_allowlist_before_std_system", "fp", "CWE-78", "t.cpp", '''#include <cstdlib>
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
    std::string cmd = "tar czf /backups/out.tgz " + it->second;
    return std::system(cmd.c_str());
}
'''),
    ("prefix_allowlist_before_curl", "fp", "CWE-918", "t.c", '''#include <curl/curl.h>
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
    url[n] = '\\0';
    if (strncmp(url, ALLOWED, strlen(ALLOWED)) != 0) {
        return;
    }
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}
'''),
    ("nested_atoi_in_snprintf_argument", "fp", "CWE-918", "t.c", '''#include <curl/curl.h>
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
    req[n] = '\\0';
    char url[600];
    snprintf(url, sizeof(url), "https://api.partner.example/items/%d", atoi(req));
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_perform(curl);
}
'''),
    # ---- buffer overflows
    ("sprintf_untrusted_into_small_buffer", "miss", "CWE-120", "t.c", HDR + '''
void send_banner(int fd)
{
    char banner[64];
    char name[256];
    ssize_t n = read(fd, name, sizeof(name) - 1);
    if (n <= 0) {
        return;
    }
    name[n] = '\\0';
    sprintf(banner, "hello %s\\n", name);
    write(fd, banner, strlen(banner));
}
'''),
    ("memcpy_length_checked_against_capacity", "fp", "CWE-120", "t.c", '''#include <stdint.h>
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
    if (len > MAX_BODY) {
        return -1;
    }
    memcpy(out->body, payload, len);
    out->len = len;
    return 0;
}
'''),

    ("tainted_index_into_global_table", "miss", "CWE-787", "t.c", '''#include <stdint.h>
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
    per_op[op] += 1;
    return per_op[0];
}
'''),
    # ---- heap lifecycle
    ("free_in_branch_then_free_on_other_path", "fp", "CWE-415", "t.c", HDR + '''
int parse_header(const char *line)
{
    char *copy = strdup(line);
    if (copy == NULL) {
        return -1;
    }
    char *colon = strchr(copy, ':');
    if (colon == NULL) {
        free(copy);
        return -1;
    }
    *colon = '\\0';
    free(copy);
    return 0;
}
'''),
    ("member_array_new_scalar_delete", "miss", "CWE-762", "t.cpp", '''#include <cstddef>

class FrameBuffer {
public:
    explicit FrameBuffer(std::size_t n) : data_(new unsigned char[n]), size_(n) {}
    ~FrameBuffer() { delete data_; }
    std::size_t size() const { return size_; }

private:
    unsigned char *data_;
    std::size_t size_;
};
'''),
    # ---- weak randomness is only reported in a file that includes a crypto header
    ("rand_for_session_token_without_crypto_include", "miss", "CWE-338", "t.c", '''#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void new_session_token(char *out, size_t len)
{
    srand((unsigned)time(NULL));
    for (size_t i = 0; i + 1 < len; i++) {
        out[i] = "0123456789abcdef"[rand() % 16];
    }
    out[len - 1] = '\\0';
}
'''),
]


@pytest.mark.xfail(strict=True, reason="known limitation (see test_known_gaps_cnative.py)")
@pytest.mark.parametrize("gap", GAPS, ids=[g[0] for g in GAPS])
def test_known_gap(gap, tmp_path):
    _name, kind, cwe, filename, source = gap
    write_tree(tmp_path, {filename: source})
    got = scan(tmp_path)
    reported = {f["cwe_id"] for f in got.findings}
    if kind == "miss":
        assert cwe in reported, f"{cwe} not reported; got {sorted(reported)}"
    else:
        assert cwe not in reported, f"false {cwe}: {[(f['line'], f['cwe_id']) for f in got.findings]}"
