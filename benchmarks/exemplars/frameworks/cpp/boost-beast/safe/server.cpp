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
        // the payload is handed over as a file; the command line is a constant
        std::ofstream payload("/var/spool/deploy/payload.json", std::ios::binary);
        payload << req.body();
        payload.close();
        std::system("/opt/deploy/run.sh /var/spool/deploy/payload.json");
        res.body() = "started";
        return res;
    }

    res.body() = "not found";
    for (const char *known : {"/index.html", "/app.js", "/style.css"}) {
        if (target == known)
            res.body() = read_file(doc_root + known);
    }
    res.set(http::field::content_type, "text/plain");
    res.prepare_payload();
    return res;
}

void handle_admin_line(tcp::socket &sock) {
    char data[512];
    std::size_t n = sock.read_some(asio::buffer(data, sizeof(data) - 1));
    data[n] = '\0';
    int level = std::atoi(data);
    std::string cmd = "/usr/bin/admin-cli --level " + std::to_string(level);
    std::system(cmd.c_str());
}
