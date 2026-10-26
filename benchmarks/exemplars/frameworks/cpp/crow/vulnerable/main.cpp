// Inventory API on Crow: lookup by name, report generation, cache purge.
#include "crow.h"
#include <sqlite3.h>
#include <cstdlib>
#include <fstream>
#include <string>

static sqlite3 *db = nullptr;

static std::string run_query(const std::string &sql) {
    std::string out;
    sqlite3_exec(db, sql.c_str(), [](void *acc, int n, char **vals, char **) {
        auto *s = static_cast<std::string *>(acc);
        for (int i = 0; i < n; i++) *s += std::string(vals[i] ? vals[i] : "") + ",";
        return 0;
    }, &out, nullptr);
    return out;
}

int main() {
    sqlite3_open("inventory.db", &db);
    crow::SimpleApp app;

    CROW_ROUTE(app, "/items")([](const crow::request &req) {
        std::string name = req.url_params.get("name") ? req.url_params.get("name") : "";
        std::string sql = "SELECT sku, qty FROM items WHERE name = '" + name + "'";
        sqlite3_exec(db, sql.c_str(), nullptr, nullptr, nullptr); /* frame-expect: CWE-89 */
        return crow::response(200, "ok");
    });

    CROW_ROUTE(app, "/report").methods("POST"_method)([](const crow::request &req) {
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400);
        std::string fmt = body["format"].s();
        std::string cmd = "report-gen --format " + fmt + " > /tmp/report.out";
        std::system(cmd.c_str()); /* frame-expect: CWE-78 */
        return crow::response(202);
    });

    CROW_ROUTE(app, "/purge/<string>")([](const std::string &bucket) {
        std::string cmd = "rm -rf /var/cache/inventory/" + bucket;
        std::system(cmd.c_str()); /* frame-expect: CWE-78 */
        return crow::response(204);
    });

    CROW_ROUTE(app, "/export/<string>")([](const std::string &file) {
        std::ifstream in("/srv/exports/" + file); /* frame-expect: CWE-22 */
        std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        return crow::response(data);
    });

    CROW_ROUTE(app, "/items/<int>")([](int id) {
        return crow::response(run_query("SELECT * FROM items WHERE id = " + std::to_string(id)));
    });

    app.port(18080).multithreaded().run();
}
