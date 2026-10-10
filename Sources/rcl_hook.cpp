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
#include <mach/thread_act.h>

extern "C" int mach_vm_read_overwrite(unsigned int task, unsigned long long addr,
                                      unsigned long long size, unsigned long long out,
                                      unsigned long long *got);
#include <pthread.h>
#include <unistd.h>
#endif

namespace rcl {

namespace {

uint64_t g_base = 0;
uint64_t g_vmsize = 0;

uint32_t *g_fn_start = nullptr;
uint32_t *g_fn_table = nullptr;
uint32_t g_fn_n = 0;

uint32_t *g_sink = nullptr;
uint32_t g_sink_n = 0;

uint32_t g_hits = 0;

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

bool rdmem(uint64_t va, void *dst, size_t n) {
    unsigned long long got = 0;
    if (mach_vm_read_overwrite(mach_task_self_, va, n, (unsigned long long)(uintptr_t)dst, &got) != 0)
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

bool sink_contains(uint64_t pc, uint32_t *out_sink) {
    if (pc < g_base || pc - g_base >= g_vmsize) return false;
    const uint32_t r = (uint32_t)(pc - g_base);
    uint32_t lo = 0, hi = g_sink_n, best = 0;
    bool found = false;
    while (lo < hi) {
        const uint32_t mid = (lo + hi) / 2;
        if (g_sink[mid] <= r) {
            best = mid;
            found = true;
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (!found) return false;
    if (r - g_sink[best] >= 0x3000) return false;
    if (out_sink) *out_sink = g_sink[best];
    return true;
}

void trace_sample(uint64_t pc, uint64_t lr, uint64_t x0, uint64_t x1) {
    if (!sink_contains(pc, nullptr)) return;
    char name[64];
    if (!ident_at(x0, name, sizeof name) && !ident_at(x1, name, sizeof name)) return;
    if (lr < g_base || lr - g_base >= g_vmsize) return;
    const uint32_t trva = table_for_rva((uint32_t)(lr - g_base));
    if (!trva) return;
    rcl_symbol_vote(trva, name, "trace");
    g_hits++;
}

void *rcl_sampler(void *) {
    for (;;) {
        thread_act_array_t list = nullptr;
        mach_msg_type_number_t cnt = 0;
        if (task_threads(mach_task_self(), &list, &cnt) == KERN_SUCCESS && list) {
            for (mach_msg_type_number_t i = 0; i < cnt; i++) {
                arm_thread_state64_t st;
                mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
                if (thread_get_state(list[i], ARM_THREAD_STATE64, (thread_state_t)&st, &sc) ==
                    KERN_SUCCESS)
                    trace_sample(st.__pc, st.__lr, st.__x[0], st.__x[1]);
                mach_port_deallocate(mach_task_self(), list[i]);
            }
            vm_deallocate(mach_task_self(), (vm_address_t)list, cnt * sizeof(thread_t));
        }
        usleep(300);
    }
    return nullptr;
}

#endif

}  // namespace

bool runtime_trace_install(const Image &img, const std::vector<ClassTable> &tables) {
#if defined(__APPLE__)
    const char *on = getenv("RCL_TRACE");
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
                if (t >= img.base && t - img.base < g_vmsize) str_seen = va;
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

    std::vector<uint32_t> picks;
    for (std::map<uint32_t, uint32_t>::iterator it = calls.begin(); it != calls.end(); ++it)
        if (it->second >= 2) picks.push_back(it->first);
    const char *mx = getenv("RCL_TRACE_MAX");
    size_t want = mx ? (size_t)strtoul(mx, nullptr, 0) : 32u;
    if (picks.size() > want) picks.resize(want);
    if (picks.empty()) {
        RCL_LOGLN("[trace] no string-sink candidates");
        return false;
    }
    std::sort(picks.begin(), picks.end());
    g_sink = (uint32_t *)malloc(sizeof(uint32_t) * picks.size());
    g_sink_n = (uint32_t)picks.size();
    for (uint32_t i = 0; i < g_sink_n; i++) g_sink[i] = picks[i];

    pthread_t th;
    if (pthread_create(&th, nullptr, rcl_sampler, nullptr) == 0) pthread_detach(th);
    RCL_LOGLN("[trace] sampling %u string sinks, fn map %u", g_sink_n, g_fn_n);
    return true;
#else
    (void)img;
    (void)tables;
    return false;
#endif
}

}  // namespace rcl
