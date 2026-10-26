// Nightly report job: REPORT_CUSTOMER selects the customer; orders live in PostgreSQL, SQLite and MySQL.
#include <SQLiteCpp/SQLiteCpp.h>
#include <cppconn/connection.h>
#include <cppconn/prepared_statement.h>
#include <cstdlib>
#include <iostream>
#include <pqxx/pqxx>
#include <string>

static void print_postgres(pqxx::connection &conn) {
    std::string customer = std::getenv("REPORT_CUSTOMER");
    pqxx::work txn(conn);
    pqxx::result rows = txn.exec_params("SELECT id, total FROM orders WHERE customer = $1", customer);
    for (const auto &row : rows)
        std::cout << row[0].c_str() << " " << row[1].c_str() << "\n";
}

static void print_sqlite() {
    std::string customer = std::getenv("REPORT_CUSTOMER");
    SQLite::Database db("orders.db");
    SQLite::Statement query(db, "SELECT id, total FROM orders WHERE customer = ?");
    query.bind(1, customer);
    while (query.executeStep())
        std::cout << query.getColumn(0) << " " << query.getColumn(1) << "\n";
}

static void print_mysql(sql::Connection *con) {
    std::string customer = std::getenv("REPORT_CUSTOMER");
    sql::PreparedStatement *stmt = con->prepareStatement("DELETE FROM carts WHERE customer = ?");
    stmt->setString(1, customer);
    stmt->execute();
    delete stmt;
}

int main() {
    pqxx::connection conn("dbname=shop");
    print_postgres(conn);
    print_sqlite();
    return 0;
}
