#ifndef POOL_H
#define POOL_H
#include <stddef.h>

/* The project's own allocator: memory from a pool, released with pool_release. */
void *pool_alloc(size_t size);
void pool_release(void *p);
/* Writes a message to the log; reads the string it is given. */
void log_message(const char *message);
/* Logs and exits. */
void fatal(const char *message);

#endif
