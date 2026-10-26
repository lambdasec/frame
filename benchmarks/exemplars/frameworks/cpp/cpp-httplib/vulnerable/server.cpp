// Notes service on cpp-httplib: user lookup, thumbnail conversion, attachment download, host check.
#include "httplib.h"
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
        std::string sql = "SELECT email FROM users WHERE name = '" + name + "'";
        std::string rows;
        sqlite3_exec(db, sql.c_str(), collect_rows, &rows, nullptr); /* frame-expect: CWE-89 */
        res.set_content("<h1>Results for " + name + "</h1><pre>" + rows + "</pre>", "text/html"); /* frame-expect: CWE-79 */
    });

    svr.Post("/thumbnail", [](const httplib::Request &req, httplib::Response &res) {
        std::string cmd = "convert " + req.body + " -resize 64x64 thumb.png";
        std::system(cmd.c_str()); /* frame-expect: CWE-78 */
        res.set_content("queued", "text/plain");
    });

    svr.Get(R"(/attachments/(.*))", [](const httplib::Request &req, httplib::Response &res) {
        std::string path = "/srv/attachments/" + std::string(req.matches[1]);
        std::ifstream in(path); /* frame-expect: CWE-22 */
        std::stringstream data;
        data << in.rdbuf();
        res.set_content(data.str(), "application/octet-stream");
    });

    svr.Get("/health/:host", [](const httplib::Request &req, httplib::Response &res) {
        std::string host = req.path_params.at("host");
        std::string cmd = "ping -c 1 " + host;
        std::system(cmd.c_str()); /* frame-expect: CWE-78 */
        res.set_content("done", "text/plain");
    });

    svr.listen("0.0.0.0", 8080);
}
