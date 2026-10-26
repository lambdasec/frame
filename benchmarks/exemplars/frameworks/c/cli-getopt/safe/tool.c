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
        if (strcmp(host, "db1.internal") == 0)
            system("ping -c 1 db1.internal");
        else if (strcmp(host, "cache1.internal") == 0)
            system("ping -c 1 cache1.internal");
    }
    if (plugin) {
        /* plugins are looked up by name in a fixed table */
        const char *path = strcmp(plugin, "audit") == 0 ? "/opt/tool/plugins/audit.so"
                         : strcmp(plugin, "report") == 0 ? "/opt/tool/plugins/report.so" : NULL;
        void *handle = path ? dlopen(path, RTLD_NOW) : NULL;
        if (handle)
            dlclose(handle);
    }
    if (message)
        printf("%s", message);
    return 0;
}
