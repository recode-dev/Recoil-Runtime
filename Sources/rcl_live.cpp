#include "rcl_live.h"
#include <thread>
#include <map>
#include <vector>
#include "rcl_log.h"
#include "rcl_alert.h"
#include "rcl_classdump.h"

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

static bool client_probe(const Image &img, uint64_t cur, LiveAnchors &a) {
    static const uint32_t m_off[] = {0x28, 0x20, 0x30, 0x18, 0x38, 0x40, 0x10, 0x48,
                                     0x50, 0x8,  0x60, 0x68, 0x70, 0x78, 0x80};
    if (!plausible_ptr(img, cur)) return false;
    for (size_t i = 0; i < sizeof(m_off) / sizeof(m_off[0]); i++) {
        uint64_t mgr = 0;
        if (!rd64(cur + m_off[i], mgr)) continue;
        uint64_t arr = 0;
        uint32_t n = 0;
        LiveAnchors probe = a;
        if (manager_fields(img, mgr, probe, arr, n)) {
            a = probe;
            a.mgr_off = m_off[i];
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

static bool discover_live(const Image &img, LiveAnchors &a) {
    a = LiveAnchors();
    if (!img.ok()) return false;

    uint64_t dlo[64], dhi[64];
    int dn = 0;
    if (!macho_data_ranges(img, dlo, dhi, 64, dn)) {
        uint64_t tlo = 0, thi = 0;
        text_span(img, tlo, thi);
        dlo[0] = thi;
        dhi[0] = img.base + (img.image_vmsize ? img.image_vmsize : img.vmsize);
        dn = 1;
    }

    for (int d = 0; d < dn && !a.ok; d++) {
        for (uint64_t va = dlo[d]; va + 8 <= dhi[d]; va += 8) {
            uint64_t home = 0;
            if (!rd64(va, home) || !plausible_ptr(img, home)) continue;
            for (uint32_t c = 0; c <= 0x200; c += 8) {
                uint64_t cur = 0;
                if (!rd64(home + c, cur) || !plausible_ptr(img, cur)) continue;
                uint64_t vt = 0;
                if (!rd64(cur, vt) || !looks_like_vtable(img, vt)) continue;
                LiveAnchors cand;
                cand.current_off = c;
                if (!client_probe(img, cur, cand)) continue;
                cand.home_slot = va;
                cand.home = home;
                cand.cur = cur;
                cand.ok = true;
                a = cand;
                break;
            }
            if (a.ok) break;
        }
    }

    if (!a.ok) return false;

    uint32_t st = 0;
    for (uint32_t s = a.current_off + 4; s <= a.current_off + 0x40; s += 4) {
        uint32_t v = 0;
        if (!rd32(a.home + s, v)) continue;
        if (v <= 31) { st = s; break; }
    }
    if (st) a.state_off = st;

    for (uint32_t s = 0x8; s <= 0x100; s += 8) {
        if (s == a.mgr_off) continue;
        uint64_t p = 0;
        if (!rd64(a.cur + s, p)) continue;
        if (!plausible_ptr(img, p)) continue;
        uint64_t vt = 0;
        if (!rd64(p, vt)) continue;
        if (looks_like_vtable(img, vt)) { a.input_off = s; break; }
    }
    return true;
}

static uint64_t g_la_base = 0;
static bool g_la_tried = false;
static LiveAnchors g_la;

static const LiveAnchors &anchors_for(const Image &img) {
    if (g_la_base != img.base) {
        g_la_base = img.base;
        g_la_tried = false;
    }
    if (!g_la_tried) {
        g_la_tried = true;
        g_la = LiveAnchors();
        const uint64_t ovh = env_u64("RCL_HOME_SLOT_RVA", 0);
        if (ovh) {
            g_la.home_slot = img.base + ovh;
            if (rd64(g_la.home_slot, g_la.home) && g_la.home) g_la.ok = true;
        } else if (!discover_live(img, g_la)) {
            RCL_LOGLN("[live] singleton not discovered; live dump will report candidates only");
        }
        if (g_la.ok) {
            g_la.state_off = (uint32_t)env_u64("RCL_STATE_OFF", g_la.state_off);
            g_la.current_off = (uint32_t)env_u64("RCL_CURRENT_OFF", g_la.current_off);
            g_la.mgr_off = (uint32_t)env_u64("RCL_MGR_OFF", g_la.mgr_off);
            g_la.input_off = (uint32_t)env_u64("RCL_INPUT_OFF", g_la.input_off);
            RCL_LOGLN("[live] singleton slot=0x%llx state=+0x%x current=+0x%x mgr=+0x%x input=+0x%x "
                      "arr=+0x%x cap=+0x%x count=+0x%x",
                      (unsigned long long)g_la.home_slot, g_la.state_off, g_la.current_off,
                      g_la.mgr_off, g_la.input_off, g_la.arr_off, g_la.cap_off, g_la.count_off);
        }
    }
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
std::map<uint64_t, uint32_t> g_bc_vt;
std::map<uint64_t, char> g_bc_slot;
std::vector<uint64_t> g_bc_want;

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
    alert_show("Recoil", "Бой начался — захват включён");
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
                    fprintf(g_bc_f, "access %u rva=0x%llx\n", g_bc_vt[t], (unsigned long long)(at - img.base));
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

void bc_close(void) {
    if (!g_bc_f) {
        g_bc_active = false;
        return;
    }
    if (!g_bc_code && g_bc_classes > 0) {
        g_bc_code = true;
        bc_code_pass(g_bc_img);
    }
    fprintf(g_bc_f, "# battle end poll=%llu classes=%u objects=%u fields=%u accessors=%u\n",
            (unsigned long long)g_bc_tick, g_bc_classes, g_bc_objects, g_bc_fields, g_bc_accessors);
    {
        char msg[256];
        snprintf(msg, sizeof msg, "Бой закончился\nклассов: %u\nполей: %u\nаксессоров: %u", g_bc_classes, g_bc_fields,
                 g_bc_accessors);
        alert_show("Recoil", msg);
    }
    fflush(g_bc_f);
    g_bc_active = false;
}

void bc_poll(const Image &img, uint32_t state, uint64_t cur, uint64_t mgr, uint64_t arr, uint32_t n) {
    bool inBattle = false;
    bc_open_file();
    if (!g_bc_f) return;
    inBattle = (state == 5 && cur != 0) || (n >= 2);
    if ((g_bc_tick % 5) == 0) {
        fprintf(g_bc_f, "poll %llu state=%u cur=0x%llx mgr=0x%llx n=%u live=%d classes=%u fields=%u\n",
                (unsigned long long)g_bc_tick, state, (unsigned long long)cur, (unsigned long long)mgr, n,
                inBattle ? 1 : 0, g_bc_classes, g_bc_fields);
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
        if (g_bc_quiet >= 10) bc_close();
    }
    if (!g_bc_active) return;
    g_bc_tick++;
    for (uint32_t i = 0; i < n && i < 256; i++) {
        uint64_t obj = 0;
        uint64_t vt = 0;
        uint64_t words[64];
        uint32_t id = 0;
        if (!bc_read(arr + (uint64_t)i * 8, &obj, 8) || !obj) continue;
        if (!bc_read(obj, &vt, 8) || !vt) continue;
        if (!bc_read(obj, words, sizeof words)) continue;
        g_bc_objects++;
        {
            std::map<uint64_t, uint32_t>::iterator it = g_bc_vt.find(vt);
            if (it == g_bc_vt.end()) {
                id = g_bc_classes++;
                g_bc_vt[vt] = id;
                g_bc_want.push_back(vt);
                fprintf(g_bc_f, "class %u vtable=0x%llx fp=0x%llx\n", id, (unsigned long long)(vt - img.base),
                        (unsigned long long)bc_fp(img, vt));
                {
                    uint64_t tlo = 0;
                    uint64_t thi = 0;
                    uint32_t slot = 0;
                    int haveText = macho_text_range(img, tlo, thi) ? 1 : 0;
                    for (slot = 0; slot < 64; slot++) {
                        uint64_t w = 0;
                        if (!bc_read(vt + (uint64_t)slot * 8, &w, 8) || w == 0) break;
                        if (w < img.base || w - img.base >= img.vmsize) break;
                        fprintf(g_bc_f, "method %u slot=%u rva=0x%llx%s\n", id, slot, (unsigned long long)(w - img.base),
                                (haveText && (w < tlo || w >= thi)) ? " data" : "");
                        g_bc_accessors++;
                    }
                    fflush(g_bc_f);
                }
            } else {
                id = it->second;
            }
        }
        for (uint32_t k = 0; k < 64; k++) {
            uint64_t key = ((uint64_t)id << 32) | (uint64_t)(k * 8);
            int kind = 0;
            if (words[k] == 0) continue;
            if (g_bc_slot.find(key) != g_bc_slot.end()) continue;
            kind = bc_kind(img, words[k]);
            g_bc_slot[key] = (char)kind;
            g_bc_fields++;
            fprintf(g_bc_f, "field %u off=0x%x kind=%s sample=0x%llx\n", id, k * 8, bc_kind_name(kind),
                    (unsigned long long)words[k]);
        }
    }
    if (!g_bc_code && g_bc_tick >= 30) {
        g_bc_code = true;
        bc_code_pass(img);
    }
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
            fprintf(g_bc_f, "# anchors home_slot=0x%llx state_off=0x%x current_off=0x%x mgr_off=0x%x\n",
                    (unsigned long long)(a.home_slot - img.base), a.state_off, a.current_off, a.mgr_off);
            fflush(g_bc_f);
        }
    }
    alert_show("Recoil", "Захват боя запущен (ждёт бой)");
    std::thread([]() {
        for (;;) {
            const LiveAnchors &a = anchors_for(g_bc_img);
            uint64_t home = 0;
            uint64_t cur = 0;
            uint64_t mgr = 0;
            uint64_t arr = 0;
            uint32_t state = 0;
            uint32_t n = 0;
            if (rd64(a.home_slot, home) && home && object_ptr(g_bc_img, home)) {
                rd32(home + a.state_off, state);
                if (rd64(home + a.current_off, cur) && cur && object_ptr(g_bc_img, cur)) {
                    LiveAnchors probe = a;
                    rd64(cur + a.mgr_off, mgr);
                    if (!manager_fields(g_bc_img, mgr, probe, arr, n)) {
                        n = 0;
                    }
                }
            }
            bc_poll(g_bc_img, state, cur, mgr, arr, n);
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
