#include "rcl_live.h"
#include <thread>
#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include "rcl_log.h"
#include "rcl_alert.h"
#include "rcl_classdump.h"
#include "rcl_names.h"
#include "rcl_btnames.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/vm_map.h>

extern "C" int mach_vm_read_overwrite(unsigned int task, unsigned long long addr, unsigned long long size,
                                      unsigned long long out, unsigned long long *got);
#endif

namespace rcl {

struct LiveAnchors {
    bool ok = false;
    uint64_t home_slot = 0;
    uint64_t home = 0;
    uint64_t cur = 0;
    uint32_t state_off = 0x50;
    uint32_t current_off = 0x48;
    uint32_t mgr_off = 0x28;
    uint32_t input_off = 0x58;
    uint32_t arr_off = 0;
    uint32_t cap_off = 8;
    uint32_t count_off = 0xc;
    bool guessed = false;
};

static bool safe_read(uint64_t va, void *dst, size_t n) {
#if defined(__APPLE__) && !defined(RCL_HOST_TEST)
    if (va == 0 || n == 0) return false;
    vm_size_t got = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(), (vm_address_t)va, (vm_size_t)n,
                                         (vm_address_t)(uintptr_t)dst, &got);
    return kr == KERN_SUCCESS && got == (vm_size_t)n;
#else
    if (va == 0 || n == 0) return false;
    memcpy(dst, (const void *)(uintptr_t)va, n);
    return true;
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

static uint64_t g_span_base = 0;
static uint64_t g_span_lo = 0;
static uint64_t g_span_hi = 0;

static void text_span(const Image &img, uint64_t &lo, uint64_t &hi) {
    if (g_span_base != img.base) {
        g_span_base = img.base;
        if (!macho_text_range(img, g_span_lo, g_span_hi)) {
            g_span_lo = img.base;
            g_span_hi = img.base + (img.vmsize ? img.vmsize : img.image_vmsize);
        }
    }
    lo = g_span_lo;
    hi = g_span_hi;
}

static bool in_image(const Image &img, uint64_t v) {
    uint64_t span = img.image_vmsize ? img.image_vmsize : img.vmsize;
    if (!span) return false;
    return v >= img.base && v < img.base + span + 0x1000ULL;
}

static bool in_text(const Image &img, uint64_t v) {
    if (!in_image(img, v)) return false;
    uint64_t lo = 0, hi = 0;
    text_span(img, lo, hi);
    return v >= lo && v < hi;
}

static bool plausible_ptr(const Image &img, uint64_t v) {
    if (v < 0x100000000ULL || v >= 0x8000000000ULL) return false;
    if ((v & 0xfULL) != 0) return false;
    return !in_image(img, v);
}

static bool object_ptr(const Image &img, uint64_t v) {
    (void)img;
    if (v < 0x100000000ULL || v >= 0x8000000000ULL) return false;
    return (v & 0x7ULL) == 0;
}

static bool looks_like_vtable(const Image &img, uint64_t v) {
    if (!in_image(img, v)) return false;
    uint64_t f0 = 0, f1 = 0;
    if (!rd64(v, f0) || !rd64(v + 8, f1)) return false;
    return in_text(img, f0) && in_text(img, f1);
}

static bool manager_fields(const Image &img, uint64_t mgr, LiveAnchors &a, uint64_t &arr,
                           uint32_t &n) {
    static const uint32_t a_off[] = {0, 8, 0x10, 0x18, 0x20, 0x28, 0x30};
    static const uint32_t c_off[] = {0xc, 0x8, 0x10, 0x4, 0x14, 0x18, 0x1c};
    if (!object_ptr(img, mgr)) return false;
    for (size_t ci = 0; ci < sizeof(c_off) / sizeof(c_off[0]); ci++) {
        uint32_t cnt = 0;
        if (!rd32(mgr + c_off[ci], cnt)) continue;
        if (cnt == 0 || cnt > 65535u) continue;
        for (size_t ai = 0; ai < sizeof(a_off) / sizeof(a_off[0]); ai++) {
            uint64_t ar = 0;
            if (!rd64(mgr + a_off[ai], ar)) continue;
            if (!object_ptr(img, ar)) continue;
            uint32_t hits = 0;
            for (uint32_t k = 0; k < 8 && k < cnt; k++) {
                uint64_t o = 0, vt = 0;
                if (!rd64(ar + (uint64_t)k * 8, o) || !object_ptr(img, o)) continue;
                if (!rd64(o, vt) || !looks_like_vtable(img, vt)) continue;
                hits++;
            }
            if (hits < 2) continue;
            a.arr_off = a_off[ai];
            a.count_off = c_off[ci];
            a.cap_off = (c_off[ci] == 0xc) ? 8u : (c_off[ci] + 4u);
            arr = ar;
            n = cnt;
            return true;
        }
    }
    return false;
}

static uint64_t env_u64(const char *name, uint64_t def) {
    const char *v = getenv(name);
    if (!v || !*v) return def;
    return strtoull(v, nullptr, 0);
}

static bool gsm_slots_from_code(const Image &img, uint64_t *out, int cap, int &count) {
    count = 0;
    uint64_t lo = 0, hi = 0;
    if (!macho_text_range(img, lo, hi)) return false;
    static const uint32_t is_state[4] = {0xB9405008u, 0x6B08003Fu, 0x1A9F17E0u, 0xD65F03C0u};
    uint64_t dlo[64], dhi[64];
    int dn = 0;
    if (!macho_data_ranges(img, dlo, dhi, 64, dn)) return false;
    uint64_t fn = 0;
    for (uint64_t at = lo; at + 16 <= hi; at += 4) {
        uint32_t w0 = 0;
        if (!img.u32(at, w0) || w0 != is_state[0]) continue;
        uint32_t w1 = 0, w2 = 0, w3 = 0;
        if (!img.u32(at + 4, w1) || !img.u32(at + 8, w2) || !img.u32(at + 12, w3)) break;
        if (w1 != is_state[1] || w2 != is_state[2] || w3 != is_state[3]) continue;
        fn = at;
        break;
    }
    if (!fn) return false;
    for (uint64_t at = lo; at + 4 <= hi; at += 4) {
        uint32_t w = 0;
        if (!img.u32(at, w)) break;
        if ((w & 0xFC000000u) != 0x94000000u) continue;
        int32_t imm = (int32_t)(w & 0x03FFFFFFu);
        if (imm & 0x02000000) imm -= 0x04000000;
        if (at + (int64_t)imm * 4 != fn) continue;
        uint64_t gi = 0;
        for (int k = 1; k <= 12; k++) {
            if (at < (uint64_t)k * 4) break;
            uint64_t q = at - (uint64_t)k * 4;
            if (q < lo) break;
            uint32_t p = 0;
            if (!img.u32(q, p)) break;
            if ((p & 0xFC000000u) != 0x94000000u) continue;
            int32_t pi = (int32_t)(p & 0x03FFFFFFu);
            if (pi & 0x02000000) pi -= 0x04000000;
            gi = q + (int64_t)pi * 4;
            break;
        }
        if (!gi || gi < lo || gi + 8 > hi) continue;
        uint32_t a0 = 0, a1 = 0;
        if (!img.u32(gi, a0) || !img.u32(gi + 4, a1)) continue;
        if ((a0 & 0x9F000000u) != 0x90000000u) continue;
        if ((a1 & 0xFFC00000u) != 0xF9400000u) continue;
        if ((a1 & 0x1Fu) != 0 || ((a1 >> 5) & 0x1Fu) != (a0 & 0x1Fu)) continue;
        int64_t immlo = (int64_t)((a0 >> 29) & 3u);
        int64_t immhi = (int64_t)((a0 >> 5) & 0x7FFFFu);
        if (immhi & 0x40000) immhi -= 0x80000;
        const uint64_t page = (gi & ~0xFFFull) + ((uint64_t)((immhi << 2) | immlo) << 12);
        const uint64_t va = page + (uint64_t)((a1 >> 10) & 0xFFFu) * 8;
        bool inside = false;
        for (int d = 0; d < dn; d++) {
            if (va >= dlo[d] && va + 8 <= dhi[d]) inside = true;
        }
        if (!inside) continue;
        bool dup = false;
        for (int i = 0; i < count; i++) {
            if (out[i] == va) dup = true;
        }
        if (dup || count >= cap) continue;
        out[count++] = va;
    }
    return count > 0;
}

static uint64_t g_slot[8];
static int g_slot_n = 0;
static uint64_t g_slot_base = 0;
static bool g_slot_scanned = false;

static bool gsm_slots(const Image &img, uint64_t *slots, int &ns) {
    if (g_slot_base != img.base) {
        g_slot_base = img.base;
        g_slot_scanned = false;
        g_slot_n = 0;
    }
    if (!g_slot_scanned) {
        g_slot_scanned = true;
        uint64_t s[8];
        int got = 0;
        if (gsm_slots_from_code(img, s, 8, got)) {
            for (int i = 0; i < got; i++) g_slot[i] = s[i];
            g_slot_n = got;
        }
    }
    for (int i = 0; i < g_slot_n; i++) slots[i] = g_slot[i];
    ns = g_slot_n;
    return ns > 0;
}

static bool discover_live(const Image &img, LiveAnchors &a) {
    a = LiveAnchors();
    if (!img.ok()) return false;
    uint64_t slots[8];
    int ns = 0;
    if (!gsm_slots(img, slots, ns)) return false;
    for (int i = 0; i < ns; i++) {
        uint64_t obj = 0;
        uint32_t st = 0;
        uint64_t scene = 0;
        if (!rd64(slots[i], obj) || !object_ptr(img, obj)) continue;
        if (!rd32(obj + 0x50, st) || st > 31) continue;
        rd64(obj + 0x48, scene);
        a.home_slot = slots[i];
        a.home = obj;
        a.cur = scene;
        a.ok = true;
        return true;
    }
    return false;
}

static uint64_t g_la_base = 0;
static bool g_la_tried = false;
static LiveAnchors g_la;

static const LiveAnchors &anchors_for(const Image &img) {
    if (g_la_base != img.base) {
        g_la_base = img.base;
        g_la_tried = false;
        g_la = LiveAnchors();
    }
    if (g_la.ok) return g_la;
    LiveAnchors cand;
    const uint64_t ovh = env_u64("RCL_HOME_SLOT_RVA", 0);
    if (ovh) {
        cand.home_slot = img.base + ovh;
        if (rd64(cand.home_slot, cand.home) && cand.home) cand.ok = true;
    } else if (!discover_live(img, cand)) {
        if (!g_la_tried) {
            g_la_tried = true;
            uint64_t slots[8];
            int ns = 0;
            const bool have = gsm_slots(img, slots, ns);
            RCL_LOGLN("[live] state slot %s (%d candidate(s)); manager not up yet, retrying",
                      have ? "resolved" : "not resolved", have ? ns : 0);
        }
        return g_la;
    }
    cand.state_off = (uint32_t)env_u64("RCL_STATE_OFF", cand.state_off);
    cand.current_off = (uint32_t)env_u64("RCL_CURRENT_OFF", cand.current_off);
    cand.mgr_off = (uint32_t)env_u64("RCL_MGR_OFF", cand.mgr_off);
    cand.input_off = (uint32_t)env_u64("RCL_INPUT_OFF", cand.input_off);
    RCL_LOGLN("[live] singleton slot=0x%llx (+0x%llx) state=+0x%x current=+0x%x mgr=+0x%x input=+0x%x "
              "arr=+0x%x cap=+0x%x count=+0x%x",
              (unsigned long long)cand.home_slot, (unsigned long long)(cand.home_slot - img.base),
              cand.state_off, cand.current_off, cand.mgr_off, cand.input_off, cand.arr_off,
              cand.cap_off, cand.count_off);
    g_la = cand;
    g_la_tried = true;
    return g_la;
}

bool live_home(const Image &img, uint64_t &home, uint32_t &state, uint64_t &cur) {
    home = 0;
    state = 0;
    cur = 0;
    const LiveAnchors &a = anchors_for(img);
    if (!a.ok) return false;
    if (!rd64(a.home_slot, home) || !object_ptr(img, home)) return false;
    rd32(home + a.state_off, state);
    rd64(home + a.current_off, cur);
    return object_ptr(img, cur);
}

bool live_chain(const Image &img, uint64_t &home_slot_rva, uint32_t &state_off,
                uint32_t &current_off, uint32_t &mgr_off, uint32_t &arr_off, uint32_t &cap_off,
                uint32_t &count_off) {
    home_slot_rva = 0;
    state_off = 0;
    current_off = 0;
    mgr_off = 0;
    arr_off = 0;
    cap_off = 0;
    count_off = 0;
    const LiveAnchors &a = anchors_for(img);
    if (!a.ok) return false;
    home_slot_rva = a.home_slot >= img.base ? a.home_slot - img.base : a.home_slot;
    state_off = a.state_off;
    current_off = a.current_off;
    mgr_off = a.mgr_off;
    arr_off = a.arr_off;
    cap_off = a.cap_off;
    count_off = a.count_off;
    return true;
}

static void fmt_ptr(const Image &img, uint64_t va, char *out, size_t n) {
    if (va == 0) snprintf(out, n, "null");
    else if (in_image(img, va)) snprintf(out, n, "rva=0x%06x", (unsigned)(va - img.base));
    else snprintf(out, n, "0x%llx", (unsigned long long)va);
}

static void fmt_rva(const Image &img, uint64_t va, char *out, size_t n) {
    if (va == 0) snprintf(out, n, "null");
    else if (in_image(img, va)) snprintf(out, n, "0x%06x", (unsigned)(va - img.base));
    else snprintf(out, n, "0x%llx", (unsigned long long)va);
}

static void dump_words(uint64_t base, int words, const char *tag) {
    for (int i = 0; i + 3 < words; i += 4) {
        uint64_t a = 0, b = 0, c = 0, d = 0;
        rd64(base + (uint64_t)i * 8, a);
        rd64(base + (uint64_t)(i + 1) * 8, b);
        rd64(base + (uint64_t)(i + 2) * 8, c);
        rd64(base + (uint64_t)(i + 3) * 8, d);
        RCL_LOGLN("   %s+0x%03x  %016llx %016llx %016llx %016llx", tag, i * 8,
                  (unsigned long long)a, (unsigned long long)b, (unsigned long long)c,
                  (unsigned long long)d);
    }
}

struct Getter {
    uint32_t slot = 0;
    uint32_t off = 0;
    char kind = 0;
};

static void fmt_getter_val(const Image &img, uint64_t o, const Getter &g, char *out, size_t cap) {
    if (g.kind == 's') {
        uint32_t bits = 0;
        rd32(o + g.off, bits);
        float f = 0;
        memcpy(&f, &bits, sizeof f);
        snprintf(out, cap, "0x%02x:[+0x%x]=%.3f", g.slot * 8, g.off, (double)f);
    } else if (g.kind == 'p') {
        uint64_t v = 0;
        rd64(o + g.off, v);
        char b[48];
        fmt_ptr(img, v, b, sizeof b);
        snprintf(out, cap, "0x%02x:[+0x%x]=%s", g.slot * 8, g.off, b);
    } else {
        uint32_t v = 0;
        rd32(o + g.off, v);
        snprintf(out, cap, "0x%02x:[+0x%x]=%d", g.slot * 8, g.off, (int)v);
    }
}

static bool vtable_valid(const Image &img, uint64_t vptr) {
    if (!vptr || !in_image(img, vptr)) return false;
    int good = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t fn = 0;
        if (rd64(vptr + (uint64_t)i * 8, fn) && in_text(img, fn)) good++;
    }
    return good >= 2;
}

static void dump_vtable(const Image &img, uint64_t vptr, int slots, const char *tag,
                        uint64_t bound) {
    if (!vptr) {
        RCL_LOGLN("[vt %s] vptr null", tag);
        return;
    }
    char p[64];
    fmt_ptr(img, vptr, p, sizeof p);
    if (!vtable_valid(img, vptr)) {
        uint64_t head = 0;
        rd64(vptr, head);
        RCL_LOGLN("[vt %s] %s is not a vtable (first qword 0x%016llx)", tag, p,
                  (unsigned long long)head);
        return;
    }
    int lim = slots;
    if (bound > vptr && (bound - vptr) % 8 == 0) {
        const uint64_t bb = (bound - vptr) / 8;
        if (bb >= 1 && bb <= (uint64_t)slots) lim = (int)bb;
    }
    RCL_LOGLN("[vt %s] vptr=%s slots=%d", tag, p, lim);
    for (int i = 0; i < lim; i++) {
        uint64_t fn = 0;
        char r[64];
        if (!rd64(vptr + (uint64_t)i * 8, fn)) {
            RCL_LOGLN("     [%2d] ?", i);
            continue;
        }
        fmt_rva(img, fn, r, sizeof r);
        RCL_LOGLN("     [%2d] off=0x%03x %s", i, i * 8, r);
    }
    if (lim < slots)
        RCL_LOGLN("     (slots past %d belong to the next vtable in the const block)", lim);
}

static uint32_t vtable_getters(const Image &img, uint64_t vptr, Getter *out, uint32_t cap) {
    uint32_t n = 0;
    if (!vtable_valid(img, vptr)) return 0;
    for (int i = 0; i < 192 && n < cap; i++) {
        uint64_t fn = 0;
        if (!rd64(vptr + (uint64_t)i * 8, fn) || !in_text(img, fn)) continue;
        uint32_t w = 0, nx = 0;
        if (!rd32(fn, w) || !rd32(fn + 4, nx) || nx != 0xD65F03C0) continue;
        if (((w >> 5) & 31) != 0) continue;
        const uint32_t m = w & 0xFFC00000, rt = w & 31;
        char kind = 0;
        uint32_t off = 0;
        if (m == 0xB9400000 && rt == 0) { kind = 'w'; off = ((w >> 10) & 0xFFF) * 4; }
        else if (m == 0xF9400000 && rt != 31) { kind = 'p'; off = ((w >> 10) & 0xFFF) * 8; }
        else if (m == 0xBD400000 && rt == 0) { kind = 's'; off = ((w >> 10) & 0xFFF) * 4; }
        else continue;
        out[n].slot = i;
        out[n].off = off;
        out[n].kind = kind;
        n++;
    }
    return n;
}

static void dump_getters(const Image &img, uint64_t vptr, int first, int last, const char *tag) {
    Getter g[96];
    const uint32_t n = vtable_getters(img, vptr, g, 96);
    for (uint32_t i = 0; i < n; i++) {
        if ((int)g[i].slot < first || (int)g[i].slot > last) continue;
        RCL_LOGLN("   %s getter slot=0x%03x  [x0,#0x%x] as %s", tag, g[i].slot * 8, g[i].off,
                  g[i].kind == 's' ? "float" : (g[i].kind == 'p' ? "ptr" : "int"));
    }
}

static void dump_object(const Image &img, uint64_t o, int idx, bool full) {
    uint64_t vt = 0;
    char p[64];
    rd64(o, vt);
    fmt_ptr(img, vt, p, sizeof p);
    uint32_t x = 0, y = 0, z = 0, own = 0, team = 0;
    uint8_t dead = 0;
    rd32(o + 0x30, x);
    rd32(o + 0x34, y);
    rd32(o + 0x38, z);
    rd32(o + 0x3c, own);
    rd32(o + 0x40, team);
    rd8(o + 0xd0, dead);
    Getter g[8];
    const uint32_t gn = vtable_getters(img, vt, g, 8);
    char vals[400];
    vals[0] = 0;
    for (uint32_t i = 0; i < gn; i++) {
        char one[96];
        fmt_getter_val(img, o, g[i], one, sizeof one);
        if (strlen(vals) + strlen(one) + 2 >= sizeof vals) break;
        if (i) strncat(vals, " ", sizeof vals - strlen(vals) - 1);
        strncat(vals, one, sizeof vals - strlen(vals) - 1);
    }
    if (!full) {
        RCL_LOGLN("  [%2d] 0x%llx vt=%s x=%d y=%d z=%d own=%d team=%d dead=%u %s", idx,
                  (unsigned long long)o, p, (int)x, (int)y, (int)z, (int)own, (int)team,
                  (unsigned)dead, vals);
        return;
    }
    RCL_LOGLN("  [%2d] 0x%llx vt=%s", idx, (unsigned long long)o, p);
    if (vals[0]) RCL_LOGLN("       getters: %s", vals);
    for (int i = 0; i + 3 < 16; i += 4) {
        uint64_t a = 0, b = 0, c = 0, d = 0;
        rd64(o + (uint64_t)i * 8, a);
        rd64(o + (uint64_t)(i + 1) * 8, b);
        rd64(o + (uint64_t)(i + 2) * 8, c);
        rd64(o + (uint64_t)(i + 3) * 8, d);
        RCL_LOGLN("       +0x%02x %016llx %016llx %016llx %016llx", i * 8,
                  (unsigned long long)a, (unsigned long long)b, (unsigned long long)c,
                  (unsigned long long)d);
    }
    RCL_LOGLN("       guess(x@0x30 y@0x34 z@0x38 owner@0x3c team@0x40 dead@0xd0) x=%d y=%d z=%d own=%d team=%d dead=%u",
              (int)x, (int)y, (int)z, (int)own, (int)team, (unsigned)dead);
}

static bool live_ident(const Image &img, uint64_t va, char *out, size_t cap) {
    if (va < img.base || va - img.base >= img.image_vmsize) return false;
    size_t i = 0;
    for (; i + 1 < cap; i++) {
        uint8_t c = 0;
        if (!rd8(va + i, c)) return false;
        if (!c) break;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_'))
            return false;
        out[i] = (char)c;
    }
    if (i < 6) return false;
    if (out[0] < 'A' || out[0] > 'Z') return false;
    out[i] = 0;
    return true;
}

static void dump_objects(const Image &img, uint64_t mgr, int objcap, int fullmax,
                          const LiveAnchors &a) {
    uint64_t arr = 0;
    uint32_t n = 0, cap = 0;
    char p[64];
    rd64(mgr + a.arr_off, arr);
    rd32(mgr + a.count_off, n);
    rd32(mgr + a.cap_off, cap);
    fmt_ptr(img, arr, p, sizeof p);
    RCL_LOGLN("[mgr] 0x%llx array=%s count=%u cap=%u full-detail-first=%d", (unsigned long long)mgr,
              p, n, cap, fullmax);
    dump_words(mgr, 16, "mgr");
    if (!arr) return;

    uint32_t lim = n;
    if (lim > (uint32_t)objcap) lim = (uint32_t)objcap;
    if (lim > 4096u) lim = 4096u;

    uint64_t vts[64];
    int nvts = 0;
    for (uint32_t i = 0; i < lim; i++) {
        uint64_t o = 0;
        if (!rd64(arr + (uint64_t)i * 8, o) || !o) {
            RCL_LOGLN("  [%2u] null", i);
            continue;
        }
        dump_object(img, o, (int)i, (int)i < fullmax);
        uint64_t v = 0;
        rd64(o, v);
        if (!v) continue;
        if (v >= img.base && v - img.base < img.image_vmsize) {
            const uint32_t trva = (uint32_t)(v - img.base);
            char id[64];
            for (uint32_t k = 0; k < 32; k++) {
                uint64_t q = 0;
                if (!rd64(o + (uint64_t)k * 8, q)) break;
                if (q < img.base || q - img.base >= img.image_vmsize) continue;
                if (!live_ident(img, q, id, sizeof id)) continue;
                rcl_symbol_vote(trva, id, "asset");
            }
        }
        int seen = 0;
        for (int q = 0; q < nvts; q++)
            if (vts[q] == v) seen = 1;
        if (!seen && nvts < 64) vts[nvts++] = v;
    }
    for (int q = 0; q < nvts; q++) {
        dump_vtable(img, vts[q], 96, "obj", 0);
    }
    RCL_LOGLN("[mgr] distinct object vptrs=%d of %u slots walked", nvts, lim);
}

static void dump_candidates(const Image &img, uint64_t base, int words, const char *tag,
                            const LiveAnchors &a) {
    RCL_LOGLN("[cand] %s fields of 0x%llx holding an (array,count) pair", tag,
              (unsigned long long)base);
    for (int i = 0; i + 1 < words; i++) {
        uint64_t p = 0;
        rd64(base + (uint64_t)i * 8, p);
        if (!plausible_ptr(img, p)) continue;
        uint64_t arr = 0, vt = 0, first = 0, fvt = 0;
        uint32_t n = 0, cap = 0;
        rd64(p + a.arr_off, arr);
        rd32(p + a.count_off, n);
        rd32(p + a.cap_off, cap);
        if (!plausible_ptr(img, arr)) continue;
        if (n == 0 || n > 65535u) continue;
        rd64(p, vt);
        if (!rd64(arr, first) || !plausible_ptr(img, first)) continue;
        if (!rd64(first, fvt) || !in_image(img, fvt)) continue;
        char b1[64], b2[64];
        fmt_ptr(img, first, b1, sizeof b1);
        fmt_ptr(img, fvt, b2, sizeof b2);
        RCL_LOGLN("   %s+0x%03x -> 0x%llx w0=0x%llx arr=0x%llx n=%u cap=%u first=%s first_vt=%s",
                  tag, i * 8, (unsigned long long)p, (unsigned long long)vt,
                  (unsigned long long)arr, n, cap, b1, b2);
    }
}

static void dump_client(const Image &img, uint64_t cur, const char *tag, int objcap, int fullmax,
                        uint64_t bound, const LiveAnchors &a) {
    uint64_t vt = 0;
    char p[64];
    rd64(cur, vt);
    fmt_ptr(img, vt, p, sizeof p);
    RCL_LOGLN("[%s] 0x%llx vptr=%s", tag, (unsigned long long)cur, p);
    dump_words(cur, 64, tag);
    dump_vtable(img, vt, 128, tag, bound);
    dump_getters(img, vt, 0, 127, tag);

    uint64_t mgr = 0, cim = 0, marr = 0;
    uint32_t mn = 0;
    rd64(cur + a.mgr_off, mgr);
    rd64(cur + a.input_off, cim);
    char m1[64], m2[64];
    fmt_ptr(img, mgr, m1, sizeof m1);
    fmt_ptr(img, cim, m2, sizeof m2);
    RCL_LOGLN("[%s] +0x%x objectManager=%s   +0x%x clientInputManager=%s", tag, a.mgr_off, m1,
              a.input_off, m2);

    LiveAnchors probe = a;
    if (manager_fields(img, mgr, probe, marr, mn)) {
        RCL_LOGLN("[battle] object manager validated mgr=0x%llx arr=0x%llx count=%u",
                  (unsigned long long)mgr, (unsigned long long)marr, mn);
        dump_objects(img, mgr, objcap, fullmax, probe);
    } else if (mgr) {
        uint64_t m0 = 0;
        uint32_t m8 = 0, m12 = 0;
        rd64(mgr, m0);
        rd32(mgr + 8, m8);
        rd32(mgr + a.count_off, m12);
        RCL_LOGLN("[%s] +0x%x = 0x%llx is not an object manager ([+0]=0x%llx [+8]=%u [+0x%x]=%u), walk skipped",
                  tag, a.mgr_off, (unsigned long long)mgr, (unsigned long long)m0, m8, a.count_off,
                  m12);
        dump_candidates(img, mgr, 16, "mgr", a);
    }
    dump_candidates(img, cur, 64, "cur", a);

    if (cim) {
        uint64_t cv = 0;
        rd64(cim, cv);
        char c1[64];
        fmt_ptr(img, cv, c1, sizeof c1);
        if (looks_like_vtable(img, cv)) {
            RCL_LOGLN("[cim] 0x%llx vptr=%s", (unsigned long long)cim, c1);
            dump_words(cim, 16, "cim");
            dump_vtable(img, cv, 64, "cim", 0);
        } else {
            RCL_LOGLN("[cim] 0x%llx has no vtable (+0x000 = %s, plain struct)",
                      (unsigned long long)cim, c1);
            dump_words(cim, 16, "cim");
        }
    }
}

static const int kGraphMax = 4096;

struct GraphNode {
    uint64_t addr;
    uint64_t from;
    uint32_t off;
    uint8_t depth;
};

static void graph_walk(const Image &img, int snap, int depth, int maxnodes, int words,
                       const LiveAnchors &a) {
    if (depth < 1) depth = 1;
    if (depth > 8) depth = 8;
    if (maxnodes < 4) maxnodes = 4;
    if (maxnodes > kGraphMax) maxnodes = kGraphMax;
    if (words < 4) words = 4;
    if (words > 128) words = 128;

    static GraphNode q[kGraphMax];
    static uint64_t vts[64];
    int n = 0, nvt = 0;

    uint64_t home = 0, cur = 0, ga = 0, gb = 0;
    uint32_t state = 0;
    rd64(a.home_slot, home);
    if (a.ok && a.home) rd32(a.home + a.state_off, state);
    if (home) rd64(home + a.current_off, cur);
    if (!home && !a.ok) {
        RCL_LOGLN("[graph] no singleton, graph skipped");
        return;
    }

    auto push = [&](uint64_t p, uint64_t from, uint32_t off, int d) {
        if (!plausible_ptr(img, p)) return;
        for (int i = 0; i < n; i++)
            if (q[i].addr == p) return;
        if (n >= maxnodes) return;
        q[n].addr = p;
        q[n].from = from;
        q[n].off = off;
        q[n].depth = (uint8_t)d;
        n++;
    };

    (void)ga;
    (void)gb;
    push(home, 0, 0, 0);
    push(cur, home, a.current_off, 0);

    RCL_LOGLN("[graph] snap=%d state=%u depth=%d maxnodes=%d words=%d", snap, state, depth,
              maxnodes, words);

    for (int i = 0; i < n; i++) {
        const GraphNode nd = q[i];
        uint64_t vt = 0;
        char p[64], f[64];
        rd64(nd.addr, vt);
        fmt_ptr(img, vt, p, sizeof p);
        if (nd.from) fmt_ptr(img, nd.from, f, sizeof f);
        else snprintf(f, sizeof f, "root");
        const bool obj = looks_like_vtable(img, vt);
        RCL_LOGLN("[gnode %3d] addr=0x%llx vt=%s obj=%s depth=%d from=%s off=0x%03x", i,
                  (unsigned long long)nd.addr, p, obj ? "yes" : "no", (int)nd.depth, f, nd.off);
        dump_words(nd.addr, words, "  g");
        for (int k = 0; k < words; k++) {
            uint64_t v = 0;
            if (!rd64(nd.addr + (uint64_t)k * 8, v) || !plausible_ptr(img, v)) continue;
            char c[64];
            fmt_ptr(img, v, c, sizeof c);
            RCL_LOGLN("   -> +0x%03x %s", k * 8, c);
            if (nd.depth < depth) push(v, nd.addr, (uint32_t)(k * 8), nd.depth + 1);
        }
        if (obj && nvt < 64) {
            bool seen = false;
            for (int z = 0; z < nvt; z++)
                if (vts[z] == vt) seen = true;
            if (!seen) vts[nvt++] = vt;
        }
    }

    for (int z = 0; z < nvt; z++) {
        dump_vtable(img, vts[z], 96, "gvt", 0);
        dump_getters(img, vts[z], 8, 95, "gvt");
    }
    RCL_LOGLN("[graph] nodes=%d of max %d, distinct object vtables=%d", n, maxnodes, nvt);
}

void live_dump(const Image &img, const Seeds &s, int snap) {
    (void)s;
    const LiveAnchors &a = anchors_for(img);

    uint64_t home = 0, cur = 0;
    uint32_t state = 0;
    if (a.ok) {
        rd64(a.home_slot, home);
        if (home) {
            rd32(home + a.state_off, state);
            rd64(home + a.current_off, cur);
        }
    }

    RCL_LOGLN("");
    RCL_LOGLN("[live #%d] home=0x%llx state=%u current=0x%llx", snap, (unsigned long long)home,
              state, (unsigned long long)cur);
    if (!a.ok) {
        RCL_LOGLN("[live #%d] singleton not discovered", snap);
        return;
    }
    RCL_LOGLN("[chain] home=*(BASE+0x%llx) state=home+0x%x current=home+0x%x mgr=current+0x%x "
              "inputMgr=current+0x%x arr=mgr+0x%x cap=mgr+0x%x count=mgr+0x%x",
              (unsigned long long)(a.home_slot - img.base), a.state_off, a.current_off, a.mgr_off,
              a.input_off, a.arr_off, a.cap_off, a.count_off);
    if (!home) {
        RCL_LOGLN("[live #%d] home singleton null", snap);
        return;
    }

    dump_words(home, 24, "home");
    uint64_t hv = 0;
    rd64(home, hv);
    dump_vtable(img, hv, 64, "home", 0);

    for (int i = 3; i < 12; i++) {
        uint64_t v = 0;
        char p[64];
        rd64(home + (uint64_t)i * 8, v);
        fmt_ptr(img, v, p, sizeof p);
        RCL_LOGLN("   home+0x%03x = %s", i * 8, p);
    }

    if (!cur) {
        RCL_LOGLN("[live #%d] no current client for state %u", snap, state);
        return;
    }

    int objcap = 512, fullmax = 64;
    const char *e = getenv("RCL_OBJ_MAX");
    if (e && *e) objcap = atoi(e);
    e = getenv("RCL_OBJ_FULL");
    if (e && *e) fullmax = atoi(e);
    if (objcap < 1) objcap = 1;
    if (objcap > 4096) objcap = 4096;
    if (fullmax < 1) fullmax = 1;
    if (fullmax > objcap) fullmax = objcap;

    dump_client(img, cur, "cur", objcap, fullmax, hv, a);

    int gdepth = 5, gmax = 1024, gwords = 32;
    bool graph = true;
    e = getenv("RCL_GRAPH");
    if (e && *e) graph = atoi(e) != 0;
    e = getenv("RCL_GRAPH_DEPTH");
    if (e && *e) gdepth = atoi(e);
    e = getenv("RCL_GRAPH_MAX");
    if (e && *e) gmax = atoi(e);
    e = getenv("RCL_GRAPH_WORDS");
    if (e && *e) gwords = atoi(e);
    bool gany = false;
    e = getenv("RCL_GRAPH_ANY");
    if (e && *e) gany = atoi(e) != 0;
    if (graph && (state == 5 || gany)) graph_walk(img, snap, gdepth, gmax, gwords, a);
}


#define RCL_MGR_ARRAY_OFF 0x0ULL
#define RCL_MGR_CAP_OFF 0x8ULL
#define RCL_MGR_COUNT_OFF 0xcULL

// ---- battle capture -------------------------------------------------------
Image g_bc_img;
FILE *g_bc_f = nullptr;
bool g_bc_active = false;
bool g_bc_done = false;
bool g_bc_code = false;
int g_bc_quiet = 0;
uint64_t g_bc_tick = 0;
uint32_t g_bc_classes = 0;
uint32_t g_bc_fields = 0;
uint32_t g_bc_objects = 0;
uint32_t g_bc_accessors = 0;
uint32_t g_bc_last_n = 0;
uint64_t g_bc_players = 0;
uint32_t g_bc_pcount = 0;
uint32_t g_bc_state = 0;
uint64_t g_bc_scene = 0;
std::map<uint64_t, uint32_t> g_bc_vt;
std::map<uint64_t, char> g_bc_slot;
std::map<uint64_t, uint64_t> g_bc_sample;
std::vector<uint64_t> g_bc_want;
struct BcAccess {
    uint32_t cls;
    uint32_t rva;
};
std::vector<BcAccess> g_bc_access;

struct BcRef {
    uint32_t pcls;
    uint32_t ccls;
    uint32_t off;
};

struct BcArr {
    uint32_t pcls;
    uint32_t ccls;
    uint32_t off;
    uint32_t via;
    uint32_t n;
    uint32_t direct;
};

std::vector<BcRef> g_bc_ref;
std::vector<BcArr> g_bc_arr;
std::map<uint64_t, uint32_t> g_bc_obj;
std::map<uint64_t, uint32_t> g_bc_cell;
bool g_bc_roots = false;
const uint32_t kBcRootCls = 0xFFFFFFFFu;

bool bc_read(uint64_t va, void *dst, size_t n) {
#if defined(__APPLE__)
    unsigned long long got = 0;
    if (!va || !n) return false;
    if (mach_vm_read_overwrite((unsigned int)mach_task_self(), (unsigned long long)va, (unsigned long long)n,
                               (unsigned long long)(uintptr_t)dst, &got) != 0)
        return false;
    return got == n;
#else
    if (!va || !n) return false;
    memcpy(dst, (const void *)(uintptr_t)va, n);
    return true;
#endif
}

int bc_kind(const Image &img, uint64_t v) {
    const uint64_t span = img.image_vmsize ? img.image_vmsize : img.vmsize;
    uint32_t lo = 0;
    uint32_t hi = 0;
    float f = 0.0f;
    float g = 0.0f;
    if (v == 0) return 0;
    if (v >= img.base && v - img.base < span) return 1;
    if ((v & 7) == 0 && v > 0x100000000ull && v < 0x800000000000ull) return 2;
    lo = (uint32_t)v;
    hi = (uint32_t)(v >> 32);
    memcpy(&f, &lo, 4);
    memcpy(&g, &hi, 4);
    if (f > -1e6f && f < 1e6f && g > -1e6f && g < 1e6f && (f != 0.0f || g != 0.0f)) return 3;
    if (v < 0x100000000ull) return 4;
    return 5;
}

const char *bc_kind_name(int k) {
    switch (k) {
        case 1: return "image_ptr";
        case 2: return "heap_ptr";
        case 3: return "vec2";
        case 4: return "int";
        case 5: return "other";
        default: return "zero";
    }
}

uint64_t bc_fp(const Image &img, uint64_t vtable) {
    uint64_t h = 1469598103934665603ull;
    for (int i = 0; i < 8; i++) {
        uint64_t w = 0;
        uint64_t rva = 0;
        if (!bc_read(vtable + (uint64_t)i * 8, &w, 8)) break;
        rva = (w >= img.base && w - img.base < img.vmsize) ? (w - img.base) : w;
        h ^= rva;
        h *= 1099511628211ull;
    }
    return h;
}

const char *bc_dir(void) {
    static char buf[1024];
    const char *home = getenv("HOME");
    if (home && *home) {
        snprintf(buf, sizeof buf, "%s/Documents", home);
        return buf;
    }
    if (log_dir() && *log_dir()) return log_dir();
    return "/tmp";
}

void bc_open_file(void) {
    char path[1200];
    if (g_bc_f) return;
    snprintf(path, sizeof path, "%s/battle-capture-log.txt", bc_dir());
    g_bc_f = fopen(path, "a");
    if (!g_bc_f) {
        snprintf(path, sizeof path, "/tmp/battle-capture-log.txt");
        g_bc_f = fopen(path, "a");
    }
    if (!g_bc_f) return;
    fprintf(g_bc_f, "# battle capture (Recoil-Runtime) opened, path=%s\n", path);
    fflush(g_bc_f);
}

void bc_open(const Image &img, uint32_t state, uint64_t cur, uint64_t mgr) {
    bc_open_file();
    if (!g_bc_f) return;
    g_bc_img = img;
    fprintf(g_bc_f, "# battle start image_base=0x%llx vmsize=0x%llx state=%u cur=0x%llx mgr=0x%llx\n",
            (unsigned long long)img.base, (unsigned long long)(img.image_vmsize ? img.image_vmsize : img.vmsize), state,
            (unsigned long long)cur, (unsigned long long)mgr);
    fprintf(g_bc_f, "# battle capture (Recoil-Runtime)\n");
    {
        char msg[160];
        snprintf(msg, sizeof msg, "Бой начался\nstate=%u count=%u\nscene=0x%llx\nplayers=0x%llx", g_bc_state, g_bc_pcount,
                 (unsigned long long)g_bc_scene, (unsigned long long)g_bc_players);
        alert_show("Recoil", msg);
    }
    fprintf(g_bc_f, "image_base=0x%llx vmsize=0x%llx state=%u cur=0x%llx mgr=0x%llx\n",
            (unsigned long long)img.base, (unsigned long long)(img.image_vmsize ? img.image_vmsize : img.vmsize),
            state, (unsigned long long)cur, (unsigned long long)mgr);
    fprintf(g_bc_f, "# class <id> vtable fp\n# field <id> off kind sample\n# access <id> rva\n");
    fflush(g_bc_f);
}

void bc_code_pass(const Image &img) {
    uint64_t lo = 0;
    uint64_t hi = 0;
    uint64_t at = 0;
    if (g_bc_want.empty()) return;
    if (!macho_text_range(img, lo, hi)) return;
    for (at = lo; at + 20 <= hi; at += 4) {
        uint32_t i0 = 0;
        uint64_t page = 0;
        if (!img.u32(at, i0)) break;
        if ((i0 & 0x9F000000u) != 0x90000000u) continue;
        {
            uint64_t immlo = (i0 >> 29) & 3u;
            int64_t immhi = (int64_t)((i0 >> 5) & 0x7FFFFu);
            if (immhi & 0x40000) immhi -= 0x80000;
            page = (at & ~0xFFFull) + ((uint64_t)((immhi << 2) | (int64_t)immlo) << 12);
        }
        for (int k = 1; k <= 4; k++) {
            uint32_t i1 = 0;
            uint64_t t = 0;
            bool hit = false;
            if (!img.u32(at + (uint64_t)k * 4, i1)) break;
            if ((i1 & 0xFF000000u) != 0x91000000u) continue;
            {
                uint64_t imm12 = (i1 >> 10) & 0xFFFu;
                uint64_t sh = (i1 >> 22) & 1u;
                t = page + imm12 * (sh ? 4096ull : 1ull);
            }
            for (size_t w = 0; w < g_bc_want.size(); w++) {
                if (t == g_bc_want[w]) {
                    BcAccess acc;
                    acc.cls = g_bc_vt[t];
                    acc.rva = (uint32_t)(at - img.base);
                    g_bc_access.push_back(acc);
                    fprintf(g_bc_f, "access %u rva=0x%llx\n", acc.cls, (unsigned long long)(at - img.base));
                    g_bc_accessors++;
                    hit = true;
                    break;
                }
            }
            if (hit) break;
        }
    }
    fflush(g_bc_f);
}

static const char *bc_class_label(const Image &img, uint64_t vt, char *buf, size_t cap) {
    if (in_image(img, vt)) {
        const uint32_t rva = (uint32_t)(vt - img.base);
        const char *n = bt_class_name(rva);
        if (n && *n) {
            const char *c = bt_class_cat(rva);
            if (c && *c)
                snprintf(buf, cap, "%s/%s", c, n);
            else
                snprintf(buf, cap, "%s", n);
            return buf;
        }
    }
    std::map<std::string, int> freq;
    for (uint32_t slot = 0; slot < 32; slot++) {
        uint64_t w = 0;
        if (!bc_read(vt + (uint64_t)slot * 8, &w, 8) || !w || !in_image(img, w)) break;
        const char *nm = name_for_rva((uint32_t)(w - img.base));
        if (!nm || strcmp(nm, "-") == 0) continue;
        const char *sep = strstr(nm, "::");
        if (!sep || sep == nm) continue;
        freq[std::string(nm, (size_t)(sep - nm))]++;
    }
    const std::string *best = nullptr;
    int bestn = 0;
    for (std::map<std::string, int>::iterator it = freq.begin(); it != freq.end(); ++it) {
        if (it->second > bestn) {
            bestn = it->second;
            best = &it->first;
        }
    }
    if (!best) {
        snprintf(buf, cap, "unknown");
        return buf;
    }
    snprintf(buf, cap, "%s", best->c_str());
    return buf;
}

static void bc_class_order(std::vector<std::pair<uint32_t, uint64_t>> &out) {
    for (std::map<uint64_t, uint32_t>::iterator it = g_bc_vt.begin(); it != g_bc_vt.end(); ++it)
        out.push_back(std::make_pair(it->second, it->first));
    std::sort(out.begin(), out.end());
}

static uint32_t bc_class_methods(const Image &img, uint64_t vt, uint64_t *rvas, uint32_t cap) {
    uint32_t k = 0;
    for (k = 0; k < cap; k++) {
        uint64_t w = 0;
        if (!bc_read(vt + (uint64_t)k * 8, &w, 8) || !w) break;
        if (!in_image(img, w)) break;
        rvas[k] = w;
    }
    return k;
}

static const char *bc_label_of(const Image &img, uint32_t id, char *buf, size_t cap) {
    if (id == kBcRootCls) {
        snprintf(buf, cap, "root");
        return buf;
    }
    uint64_t vt = 0;
    for (std::map<uint64_t, uint32_t>::iterator it = g_bc_vt.begin(); it != g_bc_vt.end(); ++it) {
        if (it->second == id) {
            vt = it->first;
            break;
        }
    }
    if (!vt) {
        snprintf(buf, cap, "unknown");
        return buf;
    }
    return bc_class_label(img, vt, buf, cap);
}

static uint64_t bc_vt_of(uint32_t id) {
    for (std::map<uint64_t, uint32_t>::iterator it = g_bc_vt.begin(); it != g_bc_vt.end(); ++it) {
        if (it->second == id) return it->first;
    }
    return 0;
}

static uint32_t bc_class_id(const Image &img, uint64_t vt) {
    std::map<uint64_t, uint32_t>::iterator it = g_bc_vt.find(vt);
    if (it != g_bc_vt.end()) return it->second;
    const uint32_t id = g_bc_classes++;
    g_bc_vt[vt] = id;
    g_bc_want.push_back(vt);
    char cls[128];
    bc_class_label(img, vt, cls, sizeof cls);
    fprintf(g_bc_f, "class %u %s vtable=0x%llx fp=0x%llx\n", id, cls,
            (unsigned long long)(vt - img.base), (unsigned long long)bc_fp(img, vt));
    uint64_t tlo = 0;
    uint64_t thi = 0;
    const int haveText = macho_text_range(img, tlo, thi) ? 1 : 0;
    for (uint32_t slot = 0; slot < 64; slot++) {
        uint64_t w = 0;
        if (!bc_read(vt + (uint64_t)slot * 8, &w, 8) || w == 0) break;
        if (w < img.base || w - img.base >= img.vmsize) break;
        fprintf(g_bc_f, "method %u slot=%u rva=0x%llx%s\n", id, slot, (unsigned long long)(w - img.base),
                (haveText && (w < tlo || w >= thi)) ? " data" : "");
        g_bc_accessors++;
    }
    return id;
}

static void bc_note_fields(const Image &img, uint32_t id, const uint64_t *words) {
    for (uint32_t k = 0; k < 64; k++) {
        if (words[k] == 0) continue;
        const uint64_t key = ((uint64_t)id << 32) | (uint64_t)(k * 8);
        if (g_bc_slot.find(key) != g_bc_slot.end()) continue;
        const int kind = bc_kind(img, words[k]);
        g_bc_slot[key] = (char)kind;
        g_bc_sample[key] = words[k];
        g_bc_fields++;
        fprintf(g_bc_f, "field %u off=0x%x kind=%s sample=0x%llx\n", id, k * 8, bc_kind_name(kind),
                (unsigned long long)words[k]);
    }
}

static uint32_t bc_note_object(const Image &img, uint64_t obj) {
    uint64_t words[64];
    if (!bc_read(obj, words, sizeof words)) return 0;
    if (!vtable_valid(img, words[0])) return 0;
    if (g_bc_obj.find(obj) != g_bc_obj.end()) return g_bc_obj[obj];
    const uint32_t id = bc_class_id(img, words[0]);
    g_bc_obj[obj] = id;
    g_bc_objects++;
    bc_note_fields(img, id, words);
    return id;
}

static void bc_note_ref(uint32_t pcls, uint32_t ccls, uint32_t off) {
    for (size_t i = 0; i < g_bc_ref.size(); i++) {
        if (g_bc_ref[i].pcls == pcls && g_bc_ref[i].ccls == ccls && g_bc_ref[i].off == off) return;
    }
    if (g_bc_ref.size() >= 8192) return;
    BcRef r;
    r.pcls = pcls;
    r.ccls = ccls;
    r.off = off;
    g_bc_ref.push_back(r);
    fprintf(g_bc_f, "ref %u off=0x%x -> %u\n", pcls, off, ccls);
}

static void bc_note_arr(uint32_t pcls, uint32_t ccls, uint32_t off, uint32_t via, uint32_t n,
                        uint32_t direct) {
    for (size_t i = 0; i < g_bc_arr.size(); i++) {
        if (g_bc_arr[i].pcls != pcls || g_bc_arr[i].via != via || g_bc_arr[i].off != off ||
            g_bc_arr[i].ccls != ccls)
            continue;
        if (g_bc_arr[i].n < n) g_bc_arr[i].n = n;
        return;
    }
    if (pcls == kBcRootCls) {
        for (size_t i = 0; i < g_bc_arr.size(); i++) {
            if (g_bc_arr[i].pcls == kBcRootCls) continue;
            if (g_bc_arr[i].via != via || g_bc_arr[i].off != off || g_bc_arr[i].ccls != ccls)
                continue;
            if (g_bc_arr[i].n < n) g_bc_arr[i].n = n;
            return;
        }
    }
    if (g_bc_arr.size() >= 4096) return;
    BcArr a;
    a.pcls = pcls;
    a.ccls = ccls;
    a.off = off;
    a.via = via;
    a.n = n;
    a.direct = direct;
    g_bc_arr.push_back(a);
    fprintf(g_bc_f, "array %u via=0x%x off=0x%x count=%u direct=%u -> %u\n", pcls, via, off, n, direct,
            ccls);
}

static bool bc_heap_ptr(const Image &img, uint64_t v) {
    if (v < 0x100000000ull || v >= 0x8000000000ull) return false;
    if ((v & 7) != 0) return false;
    return !in_image(img, v);
}

static uint32_t bc_array_len(const Image &img, uint64_t p, uint64_t &first) {
    uint32_t n = 0;
    for (uint32_t k = 0; k < 64; k++) {
        uint64_t e = 0;
        if (!bc_read(p + (uint64_t)k * 8, &e, 8)) break;
        if (!bc_heap_ptr(img, e)) break;
        uint64_t vt = 0;
        if (!bc_read(e, &vt, 8) || !vtable_valid(img, vt)) break;
        if (!k) first = e;
        n++;
    }
    return n;
}

struct BcNode {
    uint64_t addr;
    uint32_t pcls;
    uint32_t off;
    int depth;
};

static void bc_walk(const Image &img, uint64_t root, int maxDepth, int maxNodes) {
    static BcNode q[8192];
    int n = 0;
    uint32_t walked = 0;
    if (!root) return;
    auto push = [&](uint64_t a, uint32_t pc, uint32_t off, int d) {
        if (!bc_heap_ptr(img, a)) return;
        for (int i = 0; i < n; i++) {
            if (q[i].addr == a) return;
        }
        if (n >= maxNodes || n >= 8192) return;
        q[n].addr = a;
        q[n].pcls = pc;
        q[n].off = off;
        q[n].depth = d;
        n++;
    };
    push(root, kBcRootCls, 0, 0);
    for (int i = 0; i < n && walked < (uint32_t)maxNodes; i++) {
        const BcNode nd = q[i];
        if (g_bc_obj.find(nd.addr) != g_bc_obj.end()) continue;
        uint64_t words[64];
        if (!bc_read(nd.addr, words, sizeof words)) continue;
        walked++;
        const bool isObj = vtable_valid(img, words[0]);
        uint32_t id = kBcRootCls;
        if (isObj) {
            id = bc_class_id(img, words[0]);
            bc_note_object(img, nd.addr);
        }
        if (nd.depth >= maxDepth) continue;
        for (uint32_t k = 0; k < 64; k++) {
            const uint64_t w = words[k];
            if (!bc_heap_ptr(img, w)) continue;
            uint64_t wv = 0;
            if (!bc_read(w, &wv, 8)) continue;
            if (vtable_valid(img, wv)) {
                const uint32_t cid = bc_class_id(img, wv);
                if (isObj && k) bc_note_ref(id, cid, k * 8);
                push(w, id, k * 8, nd.depth + 1);
                continue;
            }
            uint64_t first = 0;
            const uint32_t cnt = bc_array_len(img, w, first);
            if (cnt < 2) {
                push(w, isObj ? id : nd.pcls, k * 8, nd.depth + 1);
                continue;
            }
            uint64_t fv = 0;
            if (!bc_read(first, &fv, 8) || !vtable_valid(img, fv)) continue;
            const uint32_t child = bc_class_id(img, fv);
            bc_note_arr(isObj ? id : nd.pcls, child, k * 8, isObj ? 0 : nd.off, cnt, isObj ? 1 : 0);
            for (uint32_t e = 0; e < cnt; e++) {
                uint64_t el = 0;
                if (!bc_read(w + (uint64_t)e * 8, &el, 8)) break;
                push(el, child, k * 8, nd.depth + 1);
            }
        }
    }
}

static void bc_scan_globals(const Image &img) {
    uint64_t lo[64];
    uint64_t hi[64];
    int dn = 0;
    if (!macho_data_ranges(img, lo, hi, 64, dn)) return;
    std::vector<uint8_t> buf(65536);
    for (int d = 0; d < dn; d++) {
        for (uint64_t at = lo[d]; at + 8 <= hi[d]; at += buf.size()) {
            uint64_t want = hi[d] - at;
            if (want > buf.size()) want = buf.size();
            want &= ~7ull;
            if (!want || !bc_read(at, buf.data(), (size_t)want)) continue;
            for (uint64_t p = 0; p + 8 <= want; p += 8) {
                uint64_t w = 0;
                memcpy(&w, buf.data() + (size_t)p, 8);
                if (!bc_heap_ptr(img, w)) continue;
                uint64_t vt = 0;
                if (!bc_read(w, &vt, 8) || !vtable_valid(img, vt)) continue;
                const uint64_t crva = at + p - img.base;
                if (g_bc_cell.find(crva) != g_bc_cell.end()) continue;
                const uint32_t id = bc_class_id(img, vt);
                g_bc_cell[crva] = id;
                fprintf(g_bc_f, "global 0x%llx -> %u\n", (unsigned long long)crva, id);
                bc_walk(img, w, 1, 128);
            }
        }
    }
}

static void bc_collect(const Image &img, uint64_t cur, uint64_t mgr) {
    if (!g_bc_roots) {
        g_bc_roots = true;
        bc_scan_globals(img);
    }
    if (mgr) bc_walk(img, mgr, 6, 2048);
    if (cur) bc_walk(img, cur, 6, 2048);
}

static void bc_write_offsets(const Image &img) {
    const char *dir = bc_dir();
    char path[1200];
    std::vector<std::pair<uint32_t, uint64_t>> cls;
    bc_class_order(cls);

    snprintf(path, sizeof path, "%s/battle-offsets.tsv", dir);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "# recoil battle offsets\n");
        fprintf(f, "# image_base=0x%llx vmsize=0x%llx state=%u scene=0x%llx players=0x%llx count=%u tick=%llu\n",
                (unsigned long long)img.base, (unsigned long long)(img.image_vmsize ? img.image_vmsize : img.vmsize),
                g_bc_state, (unsigned long long)g_bc_scene, (unsigned long long)g_bc_players,
                g_bc_pcount, (unsigned long long)g_bc_tick);
        fprintf(f, "kind\tclass_id\tclass\tslot\toff\thint\tvalue\trva\tname\n");
        for (size_t c = 0; c < cls.size(); c++) {
            const uint32_t id = cls[c].first;
            const uint64_t vt = cls[c].second;
            char label[128];
            bc_class_label(img, vt, label, sizeof label);
            fprintf(f, "class\t%u\t%s\t\t\t\t0x%llx\t0x%llx\t%s\n", id, label,
                    (unsigned long long)bc_fp(img, vt), (unsigned long long)(vt - img.base), label);
            uint64_t rvas[64];
            const uint32_t nm = bc_class_methods(img, vt, rvas, 64);
            for (uint32_t s = 0; s < nm; s++) {
                const uint32_t rva = (uint32_t)(rvas[s] - img.base);
                const char *name = name_for_rva(rva);
                fprintf(f, "method\t%u\t%s\t%u\t\t\t0x%llx\t%s\n", id, label, s, (unsigned long long)rva,
                        (name && strcmp(name, "-") != 0) ? name : "");
            }
            for (std::map<uint64_t, char>::iterator it = g_bc_slot.begin(); it != g_bc_slot.end(); ++it) {
                if ((uint32_t)(it->first >> 32) != id) continue;
                const uint32_t off = (uint32_t)(it->first & 0xffffffffu);
                std::map<uint64_t, uint64_t>::iterator sm = g_bc_sample.find(it->first);
                fprintf(f, "field\t%u\t%s\t\t0x%x\t%s\t0x%llx\t\t\n", id, label, off, bc_kind_name(it->second),
                        (unsigned long long)(sm != g_bc_sample.end() ? sm->second : 0));
            }
            for (size_t a = 0; a < g_bc_access.size(); a++) {
                if (g_bc_access[a].cls != id) continue;
                fprintf(f, "access\t%u\t%s\t\t\t\t\t0x%x\t\n", id, label, g_bc_access[a].rva);
            }
            for (size_t r = 0; r < g_bc_ref.size(); r++) {
                if (g_bc_ref[r].pcls != id) continue;
                char cl[128];
                bc_label_of(img, g_bc_ref[r].ccls, cl, sizeof cl);
                fprintf(f, "ref\t%u\t%s\t%u\t0x%x\t->class\t%s\t0x%llx\t%s\n", id, label,
                        g_bc_ref[r].ccls, g_bc_ref[r].off, cl,
                        (unsigned long long)(bc_vt_of(g_bc_ref[r].ccls) - img.base), cl);
            }
            for (size_t r = 0; r < g_bc_arr.size(); r++) {
                if (g_bc_arr[r].pcls != id) continue;
                char cl[128];
                char hint[32];
                bc_label_of(img, g_bc_arr[r].ccls, cl, sizeof cl);
                if (g_bc_arr[r].direct) snprintf(hint, sizeof hint, "array");
                else snprintf(hint, sizeof hint, "array-via=0x%x", g_bc_arr[r].via);
                fprintf(f, "container\t%u\t%s\t%u\t0x%x\t%s\t%u\t0x%llx\t%s\n", id, label,
                        g_bc_arr[r].ccls, g_bc_arr[r].off, hint, g_bc_arr[r].n,
                        (unsigned long long)(bc_vt_of(g_bc_arr[r].ccls) - img.base), cl);
            }
            for (std::map<uint64_t, uint32_t>::iterator it = g_bc_cell.begin(); it != g_bc_cell.end();
                 ++it) {
                if (it->second != id) continue;
                fprintf(f, "global\t%u\t%s\t\t\tcell\t\t0x%llx\t\n", id, label,
                        (unsigned long long)it->first);
            }
        }
        for (size_t r = 0; r < g_bc_arr.size(); r++) {
            if (g_bc_arr[r].pcls != kBcRootCls) continue;
            char cl[128];
            bc_label_of(img, g_bc_arr[r].ccls, cl, sizeof cl);
            fprintf(f, "container\t\troot\t%u\t0x%x\tarray\t%u\t0x%llx\t%s\n", g_bc_arr[r].ccls,
                    g_bc_arr[r].off, g_bc_arr[r].n,
                    (unsigned long long)(bc_vt_of(g_bc_arr[r].ccls) - img.base), cl);
        }
        fclose(f);
        RCL_LOGLN("[battle] offsets tsv written to %s", path);
    }

    snprintf(path, sizeof path, "%s/battle-offsets.md", dir);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "# Battle offsets (Recoil-Runtime)\n\n");
        fprintf(f, "- image base: `0x%llx`, vmsize `0x%llx`\n", (unsigned long long)img.base,
                (unsigned long long)(img.image_vmsize ? img.image_vmsize : img.vmsize));
        fprintf(f, "- state `%u`, scene `0x%llx`, players `0x%llx`, count `%u`, polls `%llu`\n",
                g_bc_state, (unsigned long long)g_bc_scene, (unsigned long long)g_bc_players,
                g_bc_pcount, (unsigned long long)g_bc_tick);
        fprintf(f, "- classes `%u`, objects `%u`, fields `%u`, method slots `%u`, code refs `%u`, "
                   "member refs `%u`, arrays `%u`, globals `%u`\n\n",
                g_bc_classes, g_bc_objects, g_bc_fields, g_bc_accessors, (uint32_t)g_bc_access.size(),
                (uint32_t)g_bc_ref.size(), (uint32_t)g_bc_arr.size(), (uint32_t)g_bc_cell.size());
        for (size_t c = 0; c < cls.size(); c++) {
            const uint32_t id = cls[c].first;
            const uint64_t vt = cls[c].second;
            char label[128];
            bc_class_label(img, vt, label, sizeof label);
            fprintf(f, "## class %u: %s\n\n", id, label);
            fprintf(f, "- vtable `+0x%llx` (0x%llx), fp `0x%llx`\n\n", (unsigned long long)(vt - img.base),
                    (unsigned long long)vt, (unsigned long long)bc_fp(img, vt));
            uint64_t rvas[64];
            const uint32_t nm = bc_class_methods(img, vt, rvas, 64);
            if (nm) {
                fprintf(f, "| slot | rva | name |\n|---:|---|---|\n");
                for (uint32_t s = 0; s < nm; s++) {
                    const uint32_t rva = (uint32_t)(rvas[s] - img.base);
                    const char *name = name_for_rva(rva);
                    fprintf(f, "| %u | `0x%x` | %s |\n", s, rva,
                            (name && strcmp(name, "-") != 0) ? name : "-");
                }
                fprintf(f, "\n");
            }
            fprintf(f, "| offset | kind | sample |\n|---:|---|---|\n");
            for (std::map<uint64_t, char>::iterator it = g_bc_slot.begin(); it != g_bc_slot.end(); ++it) {
                if ((uint32_t)(it->first >> 32) != id) continue;
                std::map<uint64_t, uint64_t>::iterator sm = g_bc_sample.find(it->first);
                fprintf(f, "| `0x%x` | %s | `0x%llx` |\n", (uint32_t)(it->first & 0xffffffffu),
                        bc_kind_name(it->second),
                        (unsigned long long)(sm != g_bc_sample.end() ? sm->second : 0));
            }
            fprintf(f, "\n");
            bool anyRef = false;
            for (size_t r = 0; r < g_bc_ref.size(); r++) {
                if (g_bc_ref[r].pcls != id) continue;
                if (!anyRef) {
                    fprintf(f, "| member offset | -> class |\n|---:|---|\n");
                    anyRef = true;
                }
                char cl[128];
                bc_label_of(img, g_bc_ref[r].ccls, cl, sizeof cl);
                fprintf(f, "| `0x%x` | %u %s |\n", g_bc_ref[r].off, g_bc_ref[r].ccls, cl);
            }
            if (anyRef) fprintf(f, "\n");
            bool anyArr = false;
            for (size_t r = 0; r < g_bc_arr.size(); r++) {
                if (g_bc_arr[r].pcls != id) continue;
                if (!anyArr) {
                    fprintf(f, "| array offset | count | element class |\n|---:|---:|---|\n");
                    anyArr = true;
                }
                char cl[128];
                bc_label_of(img, g_bc_arr[r].ccls, cl, sizeof cl);
                if (g_bc_arr[r].direct)
                    fprintf(f, "| `0x%x` | %u | %u %s |\n", g_bc_arr[r].off, g_bc_arr[r].n,
                            g_bc_arr[r].ccls, cl);
                else
                    fprintf(f, "| `0x%x` via `0x%x` | %u | %u %s |\n", g_bc_arr[r].off,
                            g_bc_arr[r].via, g_bc_arr[r].n, g_bc_arr[r].ccls, cl);
            }
            if (anyArr) fprintf(f, "\n");
            bool anyGlob = false;
            for (std::map<uint64_t, uint32_t>::iterator it = g_bc_cell.begin(); it != g_bc_cell.end();
                 ++it) {
                if (it->second != id) continue;
                if (!anyGlob) {
                    fprintf(f, "| global cell rva |\n|---:|\n");
                    anyGlob = true;
                }
                fprintf(f, "| `0x%llx` |\n", (unsigned long long)it->first);
            }
            if (anyGlob) fprintf(f, "\n");
            bool any = false;
            for (size_t a = 0; a < g_bc_access.size(); a++) {
                if (g_bc_access[a].cls != id) continue;
                if (!any) {
                    fprintf(f, "Code references: ");
                    any = true;
                } else {
                    fprintf(f, ", ");
                }
                fprintf(f, "`0x%x`", g_bc_access[a].rva);
            }
            if (any) fprintf(f, "\n\n");
        }
        for (size_t r = 0; r < g_bc_arr.size(); r++) {
            if (g_bc_arr[r].pcls != kBcRootCls) continue;
            char cl[128];
            bc_label_of(img, g_bc_arr[r].ccls, cl, sizeof cl);
            fprintf(f, "## root container off `0x%x`, count %u\n\n- element class %u %s\n\n",
                    g_bc_arr[r].off, g_bc_arr[r].n, g_bc_arr[r].ccls, cl);
        }
        fclose(f);
        RCL_LOGLN("[battle] offsets md written to %s", path);
    }
}

void bc_close(void) {
    if (!g_bc_f) {
        g_bc_active = false;
        return;
    }
    if (!g_bc_code && g_bc_classes > 0) {
        g_bc_code = true;
        bc_code_pass(g_bc_img);
    }
    if (g_bc_classes > 0) bc_write_offsets(g_bc_img);
    fprintf(g_bc_f, "# battle end poll=%llu classes=%u objects=%u fields=%u accessors=%u\n",
            (unsigned long long)g_bc_tick, g_bc_classes, g_bc_objects, g_bc_fields, g_bc_accessors);

    fflush(g_bc_f);
    g_bc_active = false;
}

struct BcPos
{
    uint64_t obj;
    uint32_t off;
    int32_t x;
    int32_t y;
    int valid;
};

BcPos g_bc_prev[160];
static uint64_t g_bc_pw[24][64];

int bc_container(uint64_t base, uint64_t *arrOut, uint32_t *countOut, uint32_t *capOut)
{
    uint64_t a = 0;
    uint32_t cap = 0;
    uint32_t cnt = 0;
    if (!base) return 0;
    if (!bc_read(base + RCL_MGR_ARRAY_OFF, &a, 8) || !a) return 0;
    if (!bc_read(base + RCL_MGR_CAP_OFF, &cap, 4)) return 0;
    if (!bc_read(base + RCL_MGR_COUNT_OFF, &cnt, 4)) return 0;
    if (cnt < 2 || cnt > 24 || cap < cnt) return 0;
    if (a < 0x100000000ull || a > 0x800000000000ull) return 0;
    if (arrOut) *arrOut = a;
    if (countOut) *countOut = cnt;
    if (capOut) *capOut = cap;
    return 1;
}

void bc_poll(const Image &img, uint32_t state, uint64_t cur, uint64_t mgr, uint64_t arr, uint32_t n)
{
    BcPos next[160];
    uint32_t nextN = 0;
    uint32_t i = 0;
    uint32_t j = 0;
    int inBattle = 0;
    uint32_t coordObjs = 0;
    uint32_t maxInst = 0;
    uint32_t movedInPlayers = 0;
    uint64_t players = 0;
    uint64_t pArr = 0;
    uint32_t pCount = 0;
    uint32_t pCap = 0;
    uint64_t cls[32];
    uint32_t inst[32];
    uint32_t clsN = 0;
    bc_open_file();
    if (!g_bc_f) return;
    {
        for (i = 0; i < n && i < 128; i++) {
            uint64_t obj = 0;
            uint64_t vt = 0;
            uint32_t c = 0;
            int hit = 0;
            if (!bc_read(arr + (uint64_t)i * 8, &obj, 8) || !obj) continue;
            if (!bc_read(obj, &vt, 8) || !vt) continue;
            for (c = 0; c < clsN; c++) {
                if (cls[c] == vt) {
                    inst[c]++;
                    hit = 1;
                    break;
                }
            }
            if (!hit && clsN < 32) {
                cls[clsN] = vt;
                inst[clsN] = 1;
                clsN++;
            }
        }
        for (i = 0; i < n && i < 128; i++) {
            uint64_t obj = 0;
            uint64_t vt = 0;
            uint64_t words[64];
            uint32_t off = 0;
            uint32_t c = 0;
            uint32_t instHere = 0;
            int32_t px = 0;
            int32_t py = 0;
            int found = 0;
            uint32_t k = 0;
            if (!bc_read(arr + (uint64_t)i * 8, &obj, 8) || !obj) continue;
            if (!bc_read(obj, &vt, 8) || !vt) continue;
            if (!bc_read(obj, words, sizeof words)) continue;
            for (c = 0; c < clsN; c++) {
                if (cls[c] == vt) {
                    instHere = inst[c];
                    break;
                }
            }
            for (j = 0; j < 160; j++) {
                if (g_bc_prev[j].valid && g_bc_prev[j].obj == obj && g_bc_prev[j].off < 512u) {
                    uint64_t w = words[g_bc_prev[j].off / 8];
                    off = g_bc_prev[j].off;
                    px = (int32_t)(uint32_t)w;
                    py = (int32_t)(uint32_t)(w >> 32);
                    found = 2;
                    break;
                }
            }
            if (!found) {
                for (k = 0; k < 64; k++) {
                    uint32_t lo = (uint32_t)words[k];
                    uint32_t hi = (uint32_t)(words[k] >> 32);
                    if (lo >= 200u && lo <= 40000u && hi >= 200u && hi <= 40000u) {
                        off = k * 8;
                        px = (int32_t)lo;
                        py = (int32_t)hi;
                        found = 1;
                        break;
                    }
                }
            }
            if (!found) continue;
            coordObjs++;
            if (instHere > maxInst) maxInst = instHere;
            if (nextN < 160) {
                next[nextN].obj = obj;
                next[nextN].off = off;
                next[nextN].x = px;
                next[nextN].y = py;
                next[nextN].valid = 1;
                nextN++;
            }
        }
    }
    for (i = 0; i < 160; i++) g_bc_prev[i] = i < nextN ? next[i] : BcPos{0, 0, 0, 0, 0};
    if (state == 5) {
        uint64_t cand[2];
        uint32_t ci2 = 0;
        cand[0] = mgr;
        cand[1] = cur;
        for (ci2 = 0; ci2 < 2 && !players; ci2++) {
            if (bc_container(cand[ci2], &pArr, &pCount, &pCap)) players = cand[ci2];
        }
    }
    if (players) {
        uint32_t e = 0;
        for (e = 0; e < pCount && e < 24; e++) {
            uint64_t obj = 0;
            uint64_t words[64];
            uint32_t k = 0;
            int changed = 0;
            if (!bc_read(pArr + (uint64_t)e * 8, &obj, 8) || !obj) continue;
            if (!bc_read(obj, words, sizeof words)) continue;
            for (k = 0; k < 64; k++) {
                if (g_bc_pw[e][k] != 0 && g_bc_pw[e][k] != words[k]) changed = 1;
                g_bc_pw[e][k] = words[k];
            }
            if (changed) movedInPlayers++;
        }
    }
    inBattle = (state == 5 && cur != 0);
    g_bc_players = players;
    g_bc_pcount = pCount;
    g_bc_state = state;
    g_bc_scene = cur;
    g_bc_last_n = n;
    if ((g_bc_tick % 10) == 0) {
        fprintf(g_bc_f,
                "poll %llu state=%u scene=0x%llx players=0x%llx count=%u moved=%u n=%u coord=%u inst=%u live=%d "
                "classes=%u objects=%u fields=%u arrays=%u globals=%u\n",
                (unsigned long long)g_bc_tick, state, (unsigned long long)(cur ? (cur - img.base) : 0),
                (unsigned long long)(players ? (players - img.base) : 0), pCount, movedInPlayers, n, coordObjs, maxInst,
                inBattle ? 1 : 0, g_bc_classes, g_bc_objects, g_bc_fields, (uint32_t)g_bc_arr.size(),
                (uint32_t)g_bc_cell.size());
        fflush(g_bc_f);
    }
    if (inBattle) {
        if (!g_bc_active) {
            g_bc_active = true;
            bc_open(img, state, cur, mgr);
        }
        g_bc_quiet = 0;
    } else if (g_bc_active) {
        g_bc_quiet++;
        if (g_bc_quiet >= 50) bc_close();
    }
    if (!g_bc_active) return;
    g_bc_tick++;
    if (g_bc_tick == 1 || (g_bc_tick % 120) == 0) bc_collect(img, cur, mgr);
    if (!g_bc_code && g_bc_tick >= 30) {
        g_bc_code = true;
        bc_code_pass(img);
    }
    if (g_bc_classes > 0 && (g_bc_tick % 600) == 0) bc_write_offsets(img);
    if ((g_bc_tick % 10) == 0) fflush(g_bc_f);
}


void battle_capture_open(void)
{
    bc_open_file();
}

void battle_capture_autostart(const Image &img)
{
    static bool started = false;
    if (started) return;
    started = true;
    g_bc_img = img;
    bc_open_file();
    if (g_bc_f) {
        fprintf(g_bc_f, "# autostart at image_base=0x%llx\n", (unsigned long long)img.base);
        fflush(g_bc_f);
    }
    {
        const LiveAnchors &a = anchors_for(img);
        if (g_bc_f) {
            if (a.ok)
                fprintf(g_bc_f, "# anchors home_slot=+0x%llx state_off=0x%x current_off=0x%x mgr_off=0x%x\n",
                        (unsigned long long)(a.home_slot - img.base), a.state_off, a.current_off, a.mgr_off);
            else
                fprintf(g_bc_f, "# anchors pending: state manager not created yet\n");
            fflush(g_bc_f);
        }
    }
    std::thread([]() {
        for (;;) {
            const LiveAnchors &a = anchors_for(g_bc_img);
            uint64_t gsm = 0;
            uint64_t scene = 0;
            uint64_t client = 0;
            uint64_t arr = 0;
            uint32_t state = 0;
            uint32_t n = 0;
            if (a.ok && rd64(a.home_slot, gsm) && gsm && object_ptr(g_bc_img, gsm)) {
                rd32(gsm + a.state_off, state);
                if (state == 5 && rd64(gsm + a.current_off, scene)) {
                    LiveAnchors probe = a;
                    if (scene && rd64(scene + a.mgr_off, client) && client) {
                        uint64_t carr = 0;
                        uint32_t cnt = 0;
                        uint32_t cap = 0;
                        if (bc_container(client, &carr, &cnt, &cap) ||
                            bc_container(scene, &carr, &cnt, &cap)) {
                            arr = carr;
                            n = cnt;
                        } else if (!manager_fields(g_bc_img, client, probe, arr, n)) {
                            arr = 0;
                            n = 0;
                        }
                    } else {
                        scene = 0;
                        client = 0;
                    }
                } else {
                    scene = 0;
                }
            } else {
                gsm = 0;
            }
            bc_poll(g_bc_img, state, scene, client, arr, n);
            usleep(100000);
        }
    }).detach();
}

void live_session(const Image &img, const Seeds &s) {
    int ticks = 600, ms = 2000, maxsnap = 64, battle_every = 5;
    const char *e = getenv("RCL_TICKS");
    if (e && *e) ticks = atoi(e);
    e = getenv("RCL_DUMP_MS");
    if (e && *e) ms = atoi(e);
    e = getenv("RCL_DUMP_MAX");
    if (e && *e) maxsnap = atoi(e);
    e = getenv("RCL_BATTLE_EVERY");
    if (e && *e) battle_every = atoi(e);
    if (ticks < 1) ticks = 1;
    if (ticks > 4000) ticks = 4000;
    if (ms < 200) ms = 200;
    if (ms > 60000) ms = 60000;
    if (maxsnap < 1) maxsnap = 1;
    if (maxsnap > 512) maxsnap = 512;
    if (battle_every < 1) battle_every = 1;
    if (battle_every > 1000) battle_every = 1000;

    const LiveAnchors &a = anchors_for(img);

    RCL_LOGLN("[live] window %d ticks x %d ms (%d s), max %d snapshots, battle snapshot every %d ticks",
              ticks, ms, (ticks * ms) / 1000, maxsnap, battle_every);

    uint32_t prev_state = 0xFFFFFFFFu;
    uint64_t prev_cur = 0, prev_mgr = 0;
    uint32_t prev_n = 0xFFFFFFFFu;
    int snaps = 0, since_battle = 1 << 30;
    uint32_t seen = 0;

    for (int t = 0; t < ticks && snaps < maxsnap; t++) {
        uint64_t home = 0, cur = 0, mgr = 0, marr = 0;
        uint32_t state = 0, n = 0;
        if (a.ok) rd64(a.home_slot, home);
        if (home) {
            rd32(home + a.state_off, state);
            rd64(home + a.current_off, cur);
            if (state < 32) seen |= (1u << state);
        }
        bool ok = false;
        if (cur) {
            rd64(cur + a.mgr_off, mgr);
            LiveAnchors probe = a;
            ok = manager_fields(img, mgr, probe, marr, n);
        }

        const bool changed = home && (state != prev_state || cur != prev_cur || mgr != prev_mgr ||
                                      n != prev_n);
        bool want = changed || snaps == 0;
        if (ok && since_battle >= battle_every) want = true;

        if (home)
            RCL_LOGLN("[tick %3d t=%6.1fs] state=%u cur=0x%llx mgr=0x%llx ok=%s objects=%u seen=0x%03x snap=%s",
                      t, (t * ms) / 1000.0, state, (unsigned long long)cur,
                      (unsigned long long)mgr, ok ? "yes" : "no", ok ? n : 0u, seen,
                      want ? "now" : "-");
        else
            RCL_LOGLN("[tick %3d t=%6.1fs] home singleton null", t, (t * ms) / 1000.0);

        if (want) {
            live_dump(img, s, snaps);
            snaps++;
            since_battle = 0;
        }
        since_battle++;
        prev_state = state;
        prev_cur = cur;
        prev_mgr = mgr;
        prev_n = n;
        if (snaps < maxsnap) usleep((useconds_t)ms * 1000);
    }
    RCL_LOGLN("[live] snapshots captured %d of max %d, state mask 0x%03x (state 5 %s)", snaps,
              maxsnap, seen, (seen & (1u << 5)) ? "reached" : "never reached");
}

}
