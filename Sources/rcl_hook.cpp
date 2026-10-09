// rcl_hook.cpp - pointer-slot hooking and live offset logging.
//
// We do NOT patch code. The mod this is ported from deliberately refuses to write executable pages
// and rewires function pointers instead: find the 8-byte slots that hold the target address and
// repoint them at the replacement, keeping the original for call-through. That works with PAC and
// needs no trampoline.
//
// The scan half is portable, so it is verified on the host against the real image; only the write
// half is Darwin-specific.

#include "rcl_hook.h"
#include <string.h>

namespace rcl {

int hook_scan(const Image &img, uint64_t target, uint64_t skip_lo, uint64_t skip_hi,
              std::vector<uint64_t> &slots, int max_slots) {
    slots.clear();
    const uint64_t base = img.base;
    const uint64_t end = img.base + img.vmsize;
    for (uint64_t va = base; va + 8 <= end; va += 8) {
        if (va >= skip_lo && va < skip_hi) continue;        // never look inside __text
        uint64_t v = 0;
        if (!img.read(img.ctx, va, &v, 8)) continue;
        // Two forms are accepted:
        //   loaded image  -> the slot holds the absolute VA of the target
        //   on-disk file  -> chained fixups keep the full VA in the low 36 bits, with the
        //                    bind/next/delta fields above (observed: 0x00100001007a03a0)
        if (v == target || (v & 0xFFFFFFFFFULL) == (target & 0xFFFFFFFFFULL)) {
            slots.push_back(va);
            if ((int)slots.size() >= max_slots) break;
        }
    }
    return (int)slots.size();
}

int hook_install(const Image &img, uint64_t target, uint64_t replacement,
                 uint64_t skip_lo, uint64_t skip_hi, std::vector<uint64_t> &originals,
                 int max_slots) {
    originals.clear();
    std::vector<uint64_t> slots;
    hook_scan(img, target, skip_lo, skip_hi, slots, max_slots);
    int n = 0;
    for (uint64_t slot : slots) {
        uint64_t prev = 0;
        if (!img.read(img.ctx, slot, &prev, 8)) continue;
        if (!hook_slot_write(slot, replacement)) continue;   // host build: stops here, by design
        originals.push_back(prev);
        n++;
    }
    return n;
}

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <libkern/OSCacheControl.h>

bool hook_slot_write(uint64_t slot, uint64_t value) {
    vm_address_t page = (vm_address_t)(slot & ~0xFFFULL);
    kern_return_t kr = vm_protect(mach_task_self(), page, 0x1000, false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) return false;
    memcpy((void *)slot, &value, 8);
    sys_icache_invalidate((void *)page, 0x1000);
    vm_protect(mach_task_self(), page, 0x1000, false, VM_PROT_READ | VM_PROT_EXECUTE);
    return true;
}
#else
bool hook_slot_write(uint64_t slot, uint64_t value) {
    (void)slot; (void)value;
    return false;      // host build: scanning only, no writes
}
#endif

} // namespace rcl
