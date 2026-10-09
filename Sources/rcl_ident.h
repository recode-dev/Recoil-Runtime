#ifndef RCL_IDENT_H
#define RCL_IDENT_H

#include "rcl_scan.h"

namespace rcl {

struct Stamp {
    bool probes_ok = false;
    uint32_t crc = 0;
    bool crc_ok = false;
    bool valid = false;
};

uint32_t crc32_update(uint32_t c, const uint8_t *p, size_t n);
Stamp text_stamp(const Image &img);

}

#endif
