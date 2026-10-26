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
        sqlite3_stmt *stmt = nullptr;
        sqlite3_prepare_v2(db, "SELECT sku, qty FROM items WHERE name = ?", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        std::string rows;
        while (sqlite3_step(stmt) == SQLITE_ROW)
            rows += std::string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0))) + "\n";
        sqlite3_finalize(stmt);
        return crow::response(200, rows);
    });

    CROW_ROUTE(app, "/report").methods("POST"_method)([](const crow::request &req) {
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400);
        std::string requested = body["format"].s();
        // only formats we ship; the command line is assembled from our own constants
        for (const char *known : {"pdf", "csv"}) {
            if (requested == known) {
                std::string cmd = std::string("report-gen --format ") + known + " > /tmp/report.out";
                std::system(cmd.c_str());
                return crow::response(202);
            }
        }
        return crow::response(400);
    });

    CROW_ROUTE(app, "/purge/<string>")([](const std::string &bucket) {
        for (const char *known : {"thumbs", "reports"}) {
            if (bucket == known) {
                std::string cmd = std::string("rm -rf /var/cache/inventory/") + known;
                std::system(cmd.c_str());
                return crow::response(204);
            }
        }
        return crow::response(404);
    });

    CROW_ROUTE(app, "/export/<string>")([](const std::string &file) {
        for (const char *known : {"stock.csv", "orders.csv"}) {
            if (file == known) {
                std::ifstream in(std::string("/srv/exports/") + known);
                std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                return crow::response(data);
            }
        }
        return crow::response(404);
    });

    CROW_ROUTE(app, "/items/<int>")([](int id) {
        return crow::response(run_query("SELECT * FROM items WHERE id = " + std::to_string(id)));
    });

    app.port(18080).multithreaded().run();
}
