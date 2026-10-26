// Boost.Beast HTTP server: static files, a deploy webhook, and a raw line-protocol side port.
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

static std::string read_file(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream out;
    out << in.rdbuf();
    return out.str();
}

template <class Body, class Allocator>
http::response<http::string_body>
handle_request(const std::string &doc_root, http::request<Body, http::basic_fields<Allocator>> &&req) {
    http::response<http::string_body> res{http::status::ok, req.version()};
    std::string target = std::string(req.target());

    if (req.method() == http::verb::post && target == "/hooks/deploy") {
        std::string cmd = "/opt/deploy/run.sh " + req.body();
        std::system(cmd.c_str()); /* frame-expect: CWE-78 */
        res.body() = "started";
        return res;
    }

    std::ifstream file(doc_root + target, std::ios::binary); /* frame-expect: CWE-22 */
    res.body() = file ? read_file(doc_root + target) : "not found";
    res.set(http::field::content_type, "text/plain");
    res.prepare_payload();
    return res;
}

void handle_admin_line(tcp::socket &sock) {
    char data[512];
    std::size_t n = sock.read_some(asio::buffer(data, sizeof(data) - 1));
    data[n] = '\0';
    std::string cmd = std::string("/usr/bin/admin-cli ") + data;
    std::system(cmd.c_str()); /* frame-expect: CWE-78 */
}
