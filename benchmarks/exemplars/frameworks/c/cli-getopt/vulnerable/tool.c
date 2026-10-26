/* Maintenance tool: tool -p plugin.so -h host -n count -m message */
#include <dlfcn.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int opt;
    char *plugin = NULL, *host = NULL, *message = NULL;
    while ((opt = getopt(argc, argv, "p:h:m:")) != -1) {
        switch (opt) {
        case 'p': plugin = optarg; break;
        case 'h': host = optarg; break;
        case 'm': message = optarg; break;
        default: return 2;
        }
    }
    if (host) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ping -c 1 %s", host);
        system(cmd); /* frame-expect: CWE-78 */
    }
    if (plugin) {
        void *handle = dlopen(plugin, RTLD_NOW); /* frame-expect: CWE-94 */
        if (handle)
            dlclose(handle);
    }
    if (message)
        printf(message); /* frame-expect: CWE-134 */
    return 0;
}
