#include "rcl_hook.h"
#include "rcl_classdump.h"
#include "rcl_log.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <map>
#include <vector>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>
#include <sys/mman.h>
#endif

namespace rcl {

namespace {

const uint32_t kMaxHooks = 24;

struct Target {
    uint32_t rva;
    uint32_t count;
};

uint64_t g_base = 0;
uint64_t g_vmsize = 0;
uint32_t *g_fn_start = nullptr;
uint32_t *g_fn_table = nullptr;
uint32_t g_fn_n = 0;
uint32_t g_hooked = 0;

bool is_ident(const char *s, size_t n) {
    if (n < 5 || n > 48) return false;
    if (s[0] < 'A' || s[0] > 'Z') return false;
    for (size_t i = 0; i < n; i++) {
        const char c = s[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '_')
            continue;
        return false;
    }
    return true;
}

uint32_t table_for_rva(uint32_t rva) {
    if (!g_fn_n) return 0;
    uint32_t lo = 0, hi = g_fn_n, best = 0;
    while (lo < hi) {
        const uint32_t mid = (lo + hi) / 2;
        if (g_fn_start[mid] <= rva) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (g_fn_start[best] <= rva && rva - g_fn_start[best] < 0x8000) return g_fn_table[best];
    return 0;
}

#if defined(__APPLE__)

extern "C" void rcl_runtime_shim();

__asm__(
    ".text\n"
    ".p2align 3\n"
    ".globl _rcl_runtime_shim\n"
    "_rcl_runtime_shim:\n"
    "    sub sp, sp, #0x60\n"
    "    stp x0, x1, [sp, #0x10]\n"
    "    stp x2, x3, [sp, #0x20]\n"
    "    stp x4, x5, [sp, #0x30]\n"
    "    stp x16, x30, [sp, #0x40]\n"
    "    ldp x0, x1, [sp, #0x10]\n"
    "    ldr x2, [sp, #0x48]\n"
    "    bl _rcl_hook_note\n"
    "    ldp x16, x30, [sp, #0x40]\n"
    "    ldp x4, x5, [sp, #0x30]\n"
    "    ldp x2, x3, [sp, #0x20]\n"
    "    ldp x0, x1, [sp, #0x10]\n"
    "    add sp, sp, #0x60\n"
    "    br x16\n");

bool rdmem(uint64_t va, void *dst, size_t n) {
    unsigned long long got = 0;
    if (mach_vm_read_overwrite(mach_task_self_, va, n, (unsigned long long)(uintptr_t)dst, &got) !=
        KERN_SUCCESS)
        return false;
    return got == n;
}

bool ident_at(uint64_t va, char *out, size_t cap) {
    if (va < g_base || va - g_base >= g_vmsize) return false;
    size_t i = 0;
    for (; i + 1 < cap; i++) {
        char c = 0;
        if (!rdmem(va + i, &c, 1)) return false;
        if (!c) break;
        out[i] = c;
    }
    if (i == 0) return false;
    out[i] = 0;
    return is_ident(out, i);
}

bool prologue_unsafe(uint32_t w) {
    if ((w & 0x9F000000u) == 0x90000000u) return true;
    if ((w & 0x9F000000u) == 0x10000000u) return true;
    if ((w & 0x1F000000u) == 0x10000000u) return true;
    if ((w & 0x3B000000u) == 0x18000000u) return true;
    if ((w & 0xFE000000u) == 0x54000000u) return true;
    if ((w & 0x7C000000u) == 0x14000000u) return true;
    if ((w & 0x7C000000u) == 0x94000000u) return true;
    if ((w & 0xFF800000u) == 0x91000000u) return true;
    if ((w & 0x7F800000u) == 0x11000000u) return true;
    return false;
}

void *trampoline_for(void *target) {
    void *mem = mmap(nullptr, 64, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mem == MAP_FAILED) return nullptr;
    if (!rdmem((uint64_t)(uintptr_t)target, mem, 16)) return nullptr;
    uint32_t *p = (uint32_t *)mem;
    p[4] = 0x58000050u;
    p[5] = 0xD61F0200u;
    const uint64_t back = (uint64_t)(uintptr_t)target + 16;
    memcpy((char *)mem + 24, &back, 8);
    sys_icache_invalidate(mem, 64);
    return mem;
}

bool patch_entry(void *target, void *shim, void *tramp) {
    const uintptr_t page = (uintptr_t)target & ~(uintptr_t)0xFFF;
    if (mprotect((void *)page, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return false;
    uint32_t *p = (uint32_t *)target;
    const int64_t delta = (int64_t)(uintptr_t)shim - (int64_t)((uintptr_t)target + 4);
    if (delta < -0x8000000 || delta > 0x7FFFFFC) {
        mprotect((void *)page, 0x4000, PROT_READ | PROT_EXEC);
        return false;
    }
    p[0] = 0x58000050u;
    p[1] = 0x14000000u | ((uint32_t)(delta >> 2) & 0x3FFFFFFu);
    const uint64_t tv = (uint64_t)(uintptr_t)tramp;
    memcpy((char *)target + 8, &tv, 8);
    sys_icache_invalidate(target, 16);
    mprotect((void *)page, 0x4000, PROT_READ | PROT_EXEC);
    return true;
}

#endif

}  // namespace

extern "C" void rcl_hook_note(uint64_t a0, uint64_t a1, uint64_t a2) {
#if defined(__APPLE__)
    char name[64];
    if (!ident_at(a0, name, sizeof name) && !ident_at(a1, name, sizeof name)) return;
    if (a2 < g_base || a2 - g_base >= g_vmsize) return;
    const uint32_t trva = table_for_rva((uint32_t)(a2 - g_base));
    if (!trva) return;
    rcl_symbol_vote(trva, name, "hook");
#else
    (void)a0;
    (void)a1;
    (void)a2;
#endif
}

bool runtime_hooks_install(const Image &img, const std::vector<ClassTable> &tables) {
#if defined(__APPLE__)
    const char *on = getenv("RCL_HOOKS");
    if (!on || *on != '1') return false;

    g_base = img.base;
    g_vmsize = img.image_vmsize ? img.image_vmsize : img.vmsize;

    std::vector<uint32_t> starts;
    std::vector<uint32_t> owners;
    for (size_t i = 0; i < tables.size(); i++) {
        for (uint32_t s = 0; s < tables[i].slots; s++) {
            uint64_t raw = 0;
            if (!rdmem(img.base + tables[i].start + (uint64_t)s * 8, &raw, 8)) break;
            uint32_t frva = 0;
            const uint64_t t = raw & 0xFFFFFFFFFULL;
            if (raw >= img.base && raw - img.base < g_vmsize) frva = (uint32_t)(raw - img.base);
            else if (t >= img.base && t - img.base < g_vmsize) frva = (uint32_t)(t - img.base);
            if (!frva) continue;
            starts.push_back(frva);
            owners.push_back(tables[i].start);
        }
    }
    std::vector<size_t> order(starts.size());
    for (size_t i = 0; i < order.size(); i++) order[i] = i;
    std::sort(order.begin(), order.end(),
              [&starts](size_t a, size_t b) { return starts[a] < starts[b]; });
    g_fn_n = (uint32_t)order.size();
    if (g_fn_n) {
        g_fn_start = (uint32_t *)malloc(sizeof(uint32_t) * g_fn_n);
        g_fn_table = (uint32_t *)malloc(sizeof(uint32_t) * g_fn_n);
        for (uint32_t i = 0; i < g_fn_n; i++) {
            g_fn_start[i] = starts[order[i]];
            g_fn_table[i] = owners[order[i]];
        }
    }

    std::map<uint32_t, uint32_t> calls;
    const uint64_t text_lo = img.base + 0x4000;
    const uint64_t text_hi = img.base + img.vmsize;
    const char *cs0 = getenv("RCL_STR_LO");
    const char *cs1 = getenv("RCL_STR_HI");
    const uint64_t slo = cs0 ? strtoull(cs0, nullptr, 0) : img.base;
    const uint64_t shi = cs1 ? strtoull(cs1, nullptr, 0) : 0;
    uint64_t last_page[32];
    for (int r = 0; r < 32; r++) last_page[r] = 0;
    uint64_t str_seen = 0;
    for (uint64_t va = text_lo; va + 16 < text_hi; va += 4) {
        uint32_t w = 0;
        if (!rdmem(va, &w, 4)) continue;
        if ((w & 0x9F000000u) == 0x90000000u) {
            last_page[w & 31] = va;
            continue;
        }
        if ((w & 0xFF800000u) == 0x91000000u) {
            const int rn = (w >> 5) & 31;
            uint32_t imm = (w >> 10) & 0xFFFu;
            if ((w >> 22) & 3u) imm <<= 12;
            if (last_page[rn]) {
                const uint64_t t = last_page[rn] + imm;
                if (t >= slo && (shi ? t < shi : t < img.base + g_vmsize)) str_seen = va;
            }
            continue;
        }
        if ((w & 0xFC000000u) != 0x94000000u) continue;
        if (!str_seen || va - str_seen > 0x60) continue;
        int64_t off = (int64_t)(w & 0x3FFFFFFu);
        off = (off << 38) >> 38;
        const uint64_t dst = va + (uint64_t)(off << 2);
        if (dst < text_lo || dst >= text_hi) continue;
        calls[(uint32_t)(dst - img.base)]++;
    }

    std::vector<Target> top;
    for (std::map<uint32_t, uint32_t>::iterator it = calls.begin(); it != calls.end(); ++it) {
        Target t;
        t.rva = it->first;
        t.count = it->second;
        top.push_back(t);
    }
    std::sort(top.begin(), top.end(), [](const Target &a, const Target &b) { return a.count > b.count; });

    const char *mx = getenv("RCL_HOOK_MAX");
    uint32_t want = mx ? (uint32_t)strtoul(mx, nullptr, 0) : 8u;
    if (want > kMaxHooks) want = kMaxHooks;
    uint32_t skipped = 0;
    for (size_t i = 0; i < top.size() && g_hooked < want; i++) {
        void *target = (void *)(uintptr_t)(img.base + top[i].rva);
        uint32_t w[4];
        if (!rdmem((uint64_t)(uintptr_t)target, w, sizeof w)) {
            skipped++;
            continue;
        }
        if (prologue_unsafe(w[0]) || prologue_unsafe(w[1]) || prologue_unsafe(w[2]) ||
            prologue_unsafe(w[3])) {
            skipped++;
            continue;
        }
        void *tramp = trampoline_for(target);
        if (!tramp) {
            skipped++;
            continue;
        }
        if (!patch_entry(target, (void *)(uintptr_t)rcl_runtime_shim, tramp)) {
            skipped++;
            continue;
        }
        g_hooked++;
        RCL_LOGLN("[hook] installed at %#x (string calls=%u)", top[i].rva, top[i].count);
    }
    RCL_LOGLN("[hook] candidates %u, installed %u, skipped %u", (uint32_t)top.size(), g_hooked,
              skipped);
    return g_hooked > 0;
#else
    (void)img;
    (void)tables;
    return false;
#endif
}

}  // namespace rcl
