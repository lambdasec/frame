// gRPC inventory service: lookups backed by SQLite, shell tooling, and exported files.
#include <grpcpp/grpcpp.h>
#include <sqlite3.h>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#include "inventory.grpc.pb.h"

class InventoryServiceImpl final : public inventory::Inventory::Service {
public:
    explicit InventoryServiceImpl(sqlite3 *db) : db_(db) {}

    grpc::Status FindItem(grpc::ServerContext *context, const inventory::FindRequest *request,
                          inventory::FindReply *reply) override {
        sqlite3_stmt *stmt = nullptr;
        sqlite3_prepare_v2(db_, "SELECT sku, qty FROM items WHERE name = ?", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, request->name().c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW)
            reply->add_skus(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
        sqlite3_finalize(stmt);
        return grpc::Status::OK;
    }

    grpc::Status Reindex(grpc::ServerContext *context, const inventory::ReindexRequest *request,
                         inventory::Empty *reply) override {
        // warehouses are a closed set; the command line only ever contains our own constants
        for (const char *known : {"north", "south", "east"}) {
            if (request->warehouse() == known) {
                std::string cmd = std::string("/opt/inventory/reindex --warehouse ") + known;
                std::system(cmd.c_str());
            }
        }
        return grpc::Status::OK;
    }

    grpc::Status Export(grpc::ServerContext *context, const inventory::ExportRequest *request,
                        inventory::ExportReply *reply) override {
        for (const char *known : {"stock.csv", "orders.csv"}) {
            if (request->file_name() != known)
                continue;
            std::ifstream in(std::string("/srv/exports/") + known);
            std::stringstream data;
            data << in.rdbuf();
            reply->set_content(data.str());
        }
        return grpc::Status::OK;
    }

private:
    sqlite3 *db_;
};
