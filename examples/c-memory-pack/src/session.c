#include <string.h>
#include "pool.h"

void close_session(void)
{
    char *name = pool_alloc(64);
    if (name == NULL) {
        fatal("out of memory");
    }
    strcpy(name, "guest");
    pool_release(name);
    log_message(name);
}

int session_port(int configured)
{
    int port;
    if (configured > 0) {
        port = configured;
    } else {
        fatal("no port configured");
    }
    return port;
}
