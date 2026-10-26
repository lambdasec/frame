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
        std::string sql = "SELECT sku, qty FROM items WHERE name = '" + request->name() + "'";
        sqlite3_exec(db_, sql.c_str(), &InventoryServiceImpl::on_row, reply, nullptr); /* frame-expect: CWE-89 */
        return grpc::Status::OK;
    }

    grpc::Status Reindex(grpc::ServerContext *context, const inventory::ReindexRequest *request,
                         inventory::Empty *reply) override {
        std::string cmd = "/opt/inventory/reindex --warehouse " + request->warehouse();
        std::system(cmd.c_str()); /* frame-expect: CWE-78 */
        return grpc::Status::OK;
    }

    grpc::Status Export(grpc::ServerContext *context, const inventory::ExportRequest *request,
                        inventory::ExportReply *reply) override {
        std::ifstream in("/srv/exports/" + request->file_name()); /* frame-expect: CWE-22 */
        std::stringstream data;
        data << in.rdbuf();
        reply->set_content(data.str());
        return grpc::Status::OK;
    }

private:
    static int on_row(void *out, int argc, char **argv, char **) {
        auto *reply = static_cast<inventory::FindReply *>(out);
        if (argc > 0 && argv[0]) reply->add_skus(argv[0]);
        return 0;
    }
    sqlite3 *db_;
};
