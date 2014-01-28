#include "suricata-common.h"
#include "util-json.h"
#include "util-json.h"

/* transfer string into json format */
uint8_t *prepare_json_str(uint8_t *src, uint32_t len) {
    uint32_t i;
    uint32_t out_len = len;

    uint8_t *dst = SCCalloc(out_len * 2, 1);
    if (dst == NULL)
        return NULL;

    uint8_t *p = dst;
    for (i = 0; i < len; ++i) {
        if (src[i] == '\'') {
            *p = '\\';
            ++p;
            *p = '\'';
        } else {
            *p = src[i];
        }
        ++p;
    }

    return dst;
}
