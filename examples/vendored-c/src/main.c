#include "cJSON.h"
#include "zlib.h"

int main(void) {
    cJSON *doc = cJSON_Parse("{}");
    cJSON_Delete(doc);
    return (int)zlibVersion()[0];
}
