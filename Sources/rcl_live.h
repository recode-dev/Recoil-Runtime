#ifndef RCL_LIVE_H
#define RCL_LIVE_H

#include "rcl_scan.h"

namespace rcl {

void battle_capture_open(void);
void live_dump(const Image &img, const Seeds &s, int snap);
void live_session(const Image &img, const Seeds &s);
bool live_home(const Image &img, uint64_t &home, uint32_t &state, uint64_t &cur);
bool live_chain(const Image &img, uint64_t &home_slot_rva, uint32_t &state_off,
                uint32_t &current_off, uint32_t &mgr_off, uint32_t &arr_off, uint32_t &cap_off,
                uint32_t &count_off);

}

#endif
