#include "rcl_live.h"
#include "rcl_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/vm_map.h>
#endif

namespace rcl {

static bool safe_read(uint64_t va, void *dst, size_t n) {
#if defined(__APPLE__)
    if (va == 0 || n == 0) return false;
    vm_size_t got = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)va, (vm_size_t)n,
                                         (vm_address_t)(uintptr_t)dst, &got);
    return kr == KERN_SUCCESS && got == (vm_size_t)n;
#else
    (void)va;
    (void)dst;
    (void)n;
    return false;
#endif
}

static bool rd64(uint64_t va, uint64_t &out) {
    out = 0;
    return safe_read(va, &out, sizeof out);
}

static bool rd32(uint64_t va, uint32_t &out) {
    out = 0;
    return safe_read(va, &out, sizeof out);
}

static bool rd8(uint64_t va, uint8_t &out) {
    out = 0;
    return safe_read(va, &out, sizeof out);
}

static const char *rva_of(const Image &img, uint64_t va) {
    static char b[40];
    if (va == 0) snprintf(b, sizeof b, "null");
    else if (va >= img.base && va < img.base + img.vmsize)
        snprintf(b, sizeof b, "rva=0x%06x", (unsigned)(va - img.base));
    else snprintf(b, sizeof b, "0x%llx", (unsigned long long)va);
    return b;
}

static void dump_vtable(const Image &img, uint64_t vptr, int slots, const char *tag) {
    if (!vptr) {
        RCL_LOGLN("[vt %s] vptr null", tag);
        return;
    }
    RCL_LOGLN("[vt %s] vptr=%s", tag, rva_of(img, vptr));
    for (int i = 0; i < slots; i++) {
        uint64_t fn = 0;
        if (!rd64(vptr + (uint64_t)i * 8, fn)) {
            RCL_LOGLN("     [%2d] ?", i);
            continue;
        }
        RCL_LOGLN("     [%2d] %s", i, rva_of(img, fn));
    }
}

static void dump_words(uint64_t base, int words, const char *tag) {
    for (int i = 0; i + 3 < words; i += 4) {
        uint64_t a = 0, b = 0, c = 0, d = 0;
        rd64(base + (uint64_t)i * 8, a);
        rd64(base + (uint64_t)(i + 1) * 8, b);
        rd64(base + (uint64_t)(i + 2) * 8, c);
        rd64(base + (uint64_t)(i + 3) * 8, d);
        RCL_LOGLN("   %s+0x%03x  %016llx %016llx %016llx %016llx", tag, i * 8,
                  (unsigned long long)a, (unsigned long long)b, (unsigned long long)c, (unsigned long long)d);
    }
}

static void dump_object(const Image &img, uint64_t o, int idx) {
    uint64_t vt = 0;
    rd64(o, vt);
    RCL_LOGLN("  [%2d] 0x%llx vt=%s", idx, (unsigned long long)o, rva_of(img, vt));
    for (int i = 0; i + 3 < 12; i += 4) {
        uint64_t a = 0, b = 0, c = 0, d = 0;
        rd64(o + (uint64_t)i * 8, a);
        rd64(o + (uint64_t)(i + 1) * 8, b);
        rd64(o + (uint64_t)(i + 2) * 8, c);
        rd64(o + (uint64_t)(i + 3) * 8, d);
        RCL_LOGLN("       +0x%02x %016llx %016llx %016llx %016llx", i * 8,
                  (unsigned long long)a, (unsigned long long)b, (unsigned long long)c, (unsigned long long)d);
    }
    uint32_t x = 0, y = 0, z = 0, own = 0, team = 0;
    uint8_t dead = 0;
    rd32(o + 0x30, x);
    rd32(o + 0x34, y);
    rd32(o + 0x38, z);
    rd32(o + 0x3c, own);
    rd32(o + 0x40, team);
    rd8(o + 0xd0, dead);
    RCL_LOGLN("       dec x=%d y=%d z=%d owner=%d team=%d dead=%u", (int)x, (int)y, (int)z, (int)own,
              (int)team, (unsigned)dead);
}

void live_dump(const Image &img, const Seeds &s, int snap) {
    (void)s;
    uint64_t mode = 0, ga = 0, gb = 0;
    rd64(img.base + 0x1123e58ULL, mode);
    rd64(img.base + 0x11237c8ULL, ga);
    rd64(img.base + 0x1154f50ULL, gb);
    RCL_LOGLN("");
    RCL_LOGLN("[live #%d] globals mode=0x%llx a=0x%llx b=0x%llx", snap, (unsigned long long)mode,
              (unsigned long long)ga, (unsigned long long)gb);
    if (!mode) {
        RCL_LOGLN("[live #%d] mode pointer null", snap);
        return;
    }

    uint64_t vt = 0;
    rd64(mode, vt);
    RCL_LOGLN("[live #%d] mode 0x%llx vptr=%s", snap, (unsigned long long)mode, rva_of(img, vt));
    dump_words(mode, 96, "mode");
    dump_vtable(img, vt, 40, "mode");

    static const uint64_t subs[3] = {0x28ULL, 0x58ULL, 0xf8ULL};
    for (int k = 0; k < 3; k++) {
        uint64_t sub = 0;
        rd64(mode + subs[k], sub);
        RCL_LOGLN("[live #%d] mode+0x%02llx -> 0x%llx", snap, (unsigned long long)subs[k],
                  (unsigned long long)sub);
        if (sub) dump_words(sub, 12, "sub");
    }

    uint64_t mgr = 0;
    rd64(mode + 0x28ULL, mgr);
    if (!mgr) {
        RCL_LOGLN("[live #%d] manager null", snap);
        return;
    }
    uint64_t arr = 0;
    uint32_t cnt = 0, cap = 0;
    rd64(mgr, arr);
    rd32(mgr + 0xc, cnt);
    rd32(mgr + 0x8, cap);
    RCL_LOGLN("[live #%d] mgr 0x%llx array=0x%llx count=%u cap=%u", snap, (unsigned long long)mgr,
              (unsigned long long)arr, cnt, cap);

    uint32_t lim = cnt > 48u ? 48u : cnt;
    uint64_t vts[12];
    int nvts = 0;
    for (uint32_t i = 0; i < lim; i++) {
        uint64_t o = 0;
        if (!rd64(arr + (uint64_t)i * 8, o) || !o) {
            RCL_LOGLN("  [%2u] null", i);
            continue;
        }
        dump_object(img, o, (int)i);
        uint64_t v = 0;
        rd64(o, v);
        int seen = 0;
        for (int q = 0; q < nvts; q++)
            if (vts[q] == v) seen = 1;
        if (!seen && v && nvts < 12) vts[nvts++] = v;
    }
    for (int q = 0; q < nvts; q++) dump_vtable(img, vts[q], 20, "obj");
    RCL_LOGLN("[live #%d] distinct object vptrs=%d of %u objects", snap, nvts, lim);
}

void live_session(const Image &img, const Seeds &s) {
    int maxs = 8, ms = 3000;
    const char *e = getenv("RCL_DUMP_MAX");
    if (e && *e) maxs = atoi(e);
    e = getenv("RCL_DUMP_MS");
    if (e && *e) ms = atoi(e);
    if (maxs < 1) maxs = 1;
    if (maxs > 64) maxs = 64;
    if (ms < 200) ms = 200;

    int got = 0, tries = 0;
    while (got < maxs && tries < 240) {
        uint64_t mode = 0;
        rd64(img.base + 0x1123e58ULL, mode);
        if (mode) {
            live_dump(img, s, got);
            got++;
        } else {
            RCL_LOGLN("[live] no battle yet (mode null), try %d", tries);
        }
        tries++;
        if (got < maxs) usleep((useconds_t)ms * 1000);
    }
    RCL_LOGLN("[live] snapshots captured %d (attempts %d)", got, tries);
}

}
