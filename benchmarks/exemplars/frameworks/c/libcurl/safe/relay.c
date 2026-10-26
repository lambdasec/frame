/* Link-preview relay: a TCP service that is sent a URL and returns the first bytes of the page. */
#include <curl/curl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct buffer {
    char data[8192];
    size_t len;
};

static size_t collect(char *chunk, size_t size, size_t nmemb, void *userp) {
    struct buffer *b = (struct buffer *) userp;
    size_t n = size * nmemb;
    if (b->len + n >= sizeof(b->data))
        n = sizeof(b->data) - b->len - 1;
    memcpy(b->data + b->len, chunk, n);
    b->len += n;
    return size * nmemb;
}

static void preview(int client) {
    char req[64];
    ssize_t n = recv(client, req, sizeof(req) - 1, 0);
    if (n <= 0)
        return;
    req[n] = '\0';
    /* clients name a source by number; only these upstreams may be fetched */
    static const char *const upstreams[] = {
        "https://news.example.com/latest",
        "https://blog.example.com/feed",
    };
    int which = atoi(req);
    if (which < 0 || which >= 2)
        return;
    const char *url = upstreams[which];

    struct buffer body = { .len = 0 };
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, req);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, collect);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    if (curl_easy_perform(curl) == CURLE_OK)
        write(client, body.data, body.len);
    curl_easy_cleanup(curl);
}

static int post_metrics(const char *payload) {
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://metrics.example.com/ingest");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    CURLcode rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return rc == CURLE_OK;
}

int main(void) {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(9000), .sin_addr.s_addr = INADDR_ANY };
    bind(srv, (struct sockaddr *) &addr, sizeof(addr));
    listen(srv, 16);
    for (;;) {
        int client = accept(srv, NULL, NULL);
        preview(client);
        post_metrics("previews=1");
        close(client);
    }
}
