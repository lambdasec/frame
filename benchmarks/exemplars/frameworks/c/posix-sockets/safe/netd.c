/* A line-oriented control daemon: epoll loop, one command per recv(). */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#define MAX_EVENTS 64

static void cmd_ping(int fd) {
    char line[256];
    ssize_t n = recv(fd, line, sizeof(line) - 1, 0);
    if (n <= 0)
        return;
    line[n] = '\0';
    line[strcspn(line, "\r\n")] = '\0';
    struct in_addr target;
    if (inet_pton(AF_INET, line, &target) != 1)
        return;                       /* not a dotted-quad address */
    char canonical[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &target, canonical, sizeof(canonical));
    if (fork() == 0) {
        dup2(fd, STDOUT_FILENO);
        execl("/bin/ping", "ping", "-c", "1", canonical, (char *) NULL);
        _exit(127);
    }
}

static void cmd_cat(int fd) {
    char name[128];
    ssize_t n = read(fd, name, sizeof(name) - 1);
    if (n <= 0)
        return;
    name[n] = '\0';
    char path[256];
    snprintf(path, sizeof(path), "/var/lib/netd/%s", name);
    char *real = realpath(path, NULL);
    if (real && strncmp(real, "/var/lib/netd/", 14) == 0) {
        FILE *f = fopen(real, "r");
        if (f) {
            char buf[512];
            size_t got = fread(buf, 1, sizeof(buf), f);
            write(fd, buf, got);
            fclose(f);
        }
    }
    free(real);
}

static void cmd_log(int fd) {
    char msg[200];
    ssize_t n = recvfrom(fd, msg, sizeof(msg) - 1, 0, NULL, NULL);
    if (n <= 0)
        return;
    msg[n] = '\0';
    syslog(LOG_INFO, "%s", msg);
}

int main(void) {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(7000), .sin_addr.s_addr = INADDR_ANY };
    bind(srv, (struct sockaddr *) &addr, sizeof(addr));
    listen(srv, 32);

    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = srv };
    epoll_ctl(ep, EPOLL_CTL_ADD, srv, &ev);
    struct epoll_event events[MAX_EVENTS];
    for (;;) {
        int ready = epoll_wait(ep, events, MAX_EVENTS, -1);
        for (int i = 0; i < ready; i++) {
            int fd = events[i].data.fd == srv ? accept(srv, NULL, NULL) : events[i].data.fd;
            cmd_ping(fd);
            cmd_cat(fd);
            cmd_log(fd);
        }
    }
}
