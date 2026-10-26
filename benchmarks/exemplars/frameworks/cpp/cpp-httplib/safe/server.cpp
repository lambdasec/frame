// Notes service on cpp-httplib: user lookup, thumbnail conversion, attachment download, host check.
#include "httplib.h"
#include "util.h"
#include <sqlite3.h>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

static sqlite3 *db = nullptr;

static int collect_rows(void *out, int argc, char **argv, char **) {
    auto *rows = static_cast<std::string *>(out);
    for (int i = 0; i < argc; i++)
        *rows += std::string(argv[i] ? argv[i] : "") + "\n";
    return 0;
}

int main() {
    sqlite3_open("notes.db", &db);
    httplib::Server svr;

    svr.Get("/users", [](const httplib::Request &req, httplib::Response &res) {
        std::string name = req.get_param_value("name");
        std::string rows;
        sqlite3_stmt *stmt = nullptr;
        sqlite3_prepare_v2(db, "SELECT email FROM users WHERE name = ?", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW)
            rows += std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0))) + "\n";
        sqlite3_finalize(stmt);
        res.set_content("<h1>Results for " + html_escape(name) + "</h1><pre>" + html_escape(rows) + "</pre>", "text/html");
    });

    svr.Post("/thumbnail", [](const httplib::Request &req, httplib::Response &res) {
        // the worker converts uploads/pending.bin; the request never reaches a command line
        std::ofstream pending("/var/spool/notes/pending.bin", std::ios::binary);
        pending << req.body;
        std::system("/usr/local/bin/convert-worker");
        res.set_content("queued", "text/plain");
    });

    svr.Get(R"(/attachments/(.*))", [](const httplib::Request &req, httplib::Response &res) {
        std::string wanted = "/srv/attachments/" + std::string(req.matches[1]);
        char *real = realpath(wanted.c_str(), nullptr);
        if (!real || std::string(real).rfind("/srv/attachments/", 0) != 0) {
            res.status = 404;
            free(real);
            return;
        }
        std::ifstream in(real);
        free(real);
        std::stringstream data;
        data << in.rdbuf();
        res.set_content(data.str(), "application/octet-stream");
    });

    svr.Get("/health/:host", [](const httplib::Request &req, httplib::Response &res) {
        std::string host = req.path_params.at("host");
        if (host == "db.internal")
            std::system("ping -c 1 db.internal");
        else if (host == "cache.internal")
            std::system("ping -c 1 cache.internal");
        res.set_content("done", "text/plain");
    });

    svr.listen("0.0.0.0", 8080);
}
