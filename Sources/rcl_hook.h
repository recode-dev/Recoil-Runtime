// rcl_hook.h - pointer-slot hooks for the runtime logger.
#ifndef RCL_HOOK_H
#define RCL_HOOK_H

#include "rcl_scan.h"
#include <vector>

namespace rcl {

// Collect up to max_slots 8-byte slots holding `target`, skipping [skip_lo, skip_hi) (__text).
int hook_scan(const Image &img, uint64_t target, uint64_t skip_lo, uint64_t skip_hi,
              std::vector<uint64_t> &slots, int max_slots = 64);

// Rewrite one slot. Returns false when unavailable (host build) or when the page cannot be made
// writable. Callers must keep the previous value for call-through.
bool hook_slot_write(uint64_t slot, uint64_t value);

// Convenience: scan and rewrite every slot for `target`; returns how many were rewritten and fills
// `originals` with the previous values.
int hook_install(const Image &img, uint64_t target, uint64_t replacement,
                 uint64_t skip_lo, uint64_t skip_hi, std::vector<uint64_t> &originals,
                 int max_slots = 64);

} // namespace rcl

#endif
