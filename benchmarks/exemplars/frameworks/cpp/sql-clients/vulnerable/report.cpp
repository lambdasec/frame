// Nightly report job: REPORT_CUSTOMER selects the customer; orders live in PostgreSQL, SQLite and MySQL.
#include <SQLiteCpp/SQLiteCpp.h>
#include <cppconn/connection.h>
#include <cppconn/statement.h>
#include <cstdlib>
#include <iostream>
#include <pqxx/pqxx>
#include <string>

static void print_postgres(pqxx::connection &conn) {
    std::string customer = std::getenv("REPORT_CUSTOMER");
    pqxx::work txn(conn);
    pqxx::result rows = txn.exec("SELECT id, total FROM orders WHERE customer = '" + customer + "'"); /* frame-expect: CWE-89 */
    for (const auto &row : rows)
        std::cout << row[0].c_str() << " " << row[1].c_str() << "\n";
}

static void print_sqlite() {
    std::string customer = std::getenv("REPORT_CUSTOMER");
    SQLite::Database db("orders.db");
    SQLite::Statement query(db, "SELECT id, total FROM orders WHERE customer = '" + customer + "'"); /* frame-expect: CWE-89 */
    while (query.executeStep())
        std::cout << query.getColumn(0) << " " << query.getColumn(1) << "\n";
}

static void print_mysql(sql::Connection *con) {
    std::string customer = std::getenv("REPORT_CUSTOMER");
    sql::Statement *stmt = con->createStatement();
    stmt->execute("DELETE FROM carts WHERE customer = '" + customer + "'"); /* frame-expect: CWE-89 */
    delete stmt;
}

int main() {
    pqxx::connection conn("dbname=shop");
    print_postgres(conn);
    print_sqlite();
    return 0;
}
