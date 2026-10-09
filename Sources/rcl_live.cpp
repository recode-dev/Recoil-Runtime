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

static const uint64_t kHomeGlobal     = 0x1123e58ULL;
static const uint64_t kHomeStateOff   = 0x50ULL;
static const uint64_t kHomeCurrentOff = 0x48ULL;
static const uint64_t kClientMgrOff   = 0x28ULL;
static const uint64_t kClientInputOff = 0x58ULL;
static const uint64_t kMgrArrayOff    = 0x0ULL;
static const uint64_t kMgrCapOff      = 0x8ULL;
static const uint64_t kMgrCountOff    = 0xcULL;
static const uint64_t kAuxGlobalA     = 0x11237c8ULL;
static const uint64_t kAuxGlobalB     = 0x1154f50ULL;
static const uint64_t kTextLo         = 0x4000ULL;
static const uint64_t kTextHi         = 0xd8af60ULL;

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

static bool in_image(const Image &img, uint64_t v) {
    uint64_t span = img.image_vmsize ? img.image_vmsize : img.vmsize;
    if (!span) return false;
    return v >= img.base && v < img.base + span + 0x1000ULL;
}

static bool in_text(const Image &img, uint64_t v) {
    if (!in_image(img, v)) return false;
    const uint64_t r = v - img.base;
    return r >= kTextLo && r < kTextHi;
}

static bool plausible_ptr(const Image &img, uint64_t v) {
    if (v < 0x100000000ULL || v >= 0x8000000000ULL) return false;
    if ((v & 0xfULL) != 0) return false;
    return !in_image(img, v);
}

static bool looks_like_vtable(const Image &img, uint64_t v) {
    if (!in_image(img, v)) return false;
    uint64_t f0 = 0, f1 = 0;
    if (!rd64(v, f0) || !rd64(v + 8, f1)) return false;
    return in_text(img, f0) && in_text(img, f1);
}

static bool manager_ok(const Image &img, uint64_t mgr, uint64_t &arr, uint32_t &n) {
    arr = 0;
    n = 0;
    if (!plausible_ptr(img, mgr)) return false;
    rd64(mgr + kMgrArrayOff, arr);
    rd32(mgr + kMgrCountOff, n);
    if (!plausible_ptr(img, arr)) return false;
    if (n == 0 || n > 4096u) return false;
    uint64_t o = 0, vt = 0;
    if (!rd64(arr, o) || !plausible_ptr(img, o)) return false;
    if (!rd64(o, vt) || !looks_like_vtable(img, vt)) return false;
    int good = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t fn = 0;
        if (rd64(vt + (uint64_t)i * 8, fn) && in_text(img, fn)) good++;
    }
    return good >= 2;
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
    for (int i = 0; i < 48 && n < cap; i++) {
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
    Getter g[24];
    const uint32_t n = vtable_getters(img, vptr, g, 24);
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
    for (int i = 0; i + 3 < 12; i += 4) {
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

static void dump_objects(const Image &img, uint64_t mgr, int objcap, int fullmax) {
    uint64_t arr = 0;
    uint32_t n = 0, cap = 0;
    char p[64];
    rd64(mgr + kMgrArrayOff, arr);
    rd32(mgr + kMgrCountOff, n);
    rd32(mgr + kMgrCapOff, cap);
    fmt_ptr(img, arr, p, sizeof p);
    RCL_LOGLN("[mgr] 0x%llx array=%s count=%u cap=%u full-detail-first=%d",
              (unsigned long long)mgr, p, n, cap, fullmax);
    dump_words(mgr, 16, "mgr");
    if (!arr) return;

    uint32_t lim = n;
    if (lim > (uint32_t)objcap) lim = (uint32_t)objcap;
    if (lim > 256u) lim = 256u;

    uint64_t vts[8];
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
        int seen = 0;
        for (int q = 0; q < nvts; q++)
            if (vts[q] == v) seen = 1;
        if (!seen && nvts < 8) vts[nvts++] = v;
    }
    for (int q = 0; q < nvts; q++) {
        dump_vtable(img, vts[q], 24, "obj", 0);

    }
    RCL_LOGLN("[mgr] distinct object vptrs=%d of %u slots walked", nvts, lim);
}

static void dump_candidates(const Image &img, uint64_t base, int words, const char *tag) {
    RCL_LOGLN("[cand] %s fields of 0x%llx holding an (array,count) pair", tag,
              (unsigned long long)base);
    for (int i = 0; i + 1 < words; i++) {
        uint64_t p = 0;
        rd64(base + (uint64_t)i * 8, p);
        if (!plausible_ptr(img, p)) continue;
        uint64_t arr = 0, vt = 0, first = 0, fvt = 0;
        uint32_t n = 0, cap = 0;
        rd64(p + kMgrArrayOff, arr);
        rd32(p + kMgrCountOff, n);
        rd32(p + kMgrCapOff, cap);
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
                        uint64_t bound) {
    uint64_t vt = 0;
    char p[64];
    rd64(cur, vt);
    fmt_ptr(img, vt, p, sizeof p);
    RCL_LOGLN("[%s] 0x%llx vptr=%s", tag, (unsigned long long)cur, p);
    dump_words(cur, 64, tag);
    dump_vtable(img, vt, 48, tag, bound);
    dump_getters(img, vt, 0, 47, tag);

    uint64_t mgr = 0, cim = 0, marr = 0;
    uint32_t mn = 0;
    rd64(cur + kClientMgrOff, mgr);
    rd64(cur + kClientInputOff, cim);
    char m1[64], m2[64];
    fmt_ptr(img, mgr, m1, sizeof m1);
    fmt_ptr(img, cim, m2, sizeof m2);
    RCL_LOGLN("[%s] +0x28 objectManager=%s   +0x58 clientInputManager=%s", tag, m1, m2);

    if (manager_ok(img, mgr, marr, mn)) {
        RCL_LOGLN("[battle] object manager validated mgr=0x%llx arr=0x%llx count=%u",
                  (unsigned long long)mgr, (unsigned long long)marr, mn);
        dump_objects(img, mgr, objcap, fullmax);
    } else if (mgr) {
        uint64_t m0 = 0;
        uint32_t m8 = 0, m12 = 0;
        rd64(mgr, m0);
        rd32(mgr + 8, m8);
        rd32(mgr + kMgrCountOff, m12);
        RCL_LOGLN("[%s] +0x28 = 0x%llx is not an object manager ([+0]=0x%llx [+8]=%u [+0xc]=%u), walk skipped",
                  tag, (unsigned long long)mgr, (unsigned long long)m0, m8, m12);
        dump_candidates(img, mgr, 16, "mgr");
    }
    dump_candidates(img, cur, 64, "cur");

    if (cim) {
        uint64_t cv = 0;
        rd64(cim, cv);
        char c1[64];
        fmt_ptr(img, cv, c1, sizeof c1);
        if (looks_like_vtable(img, cv)) {
            RCL_LOGLN("[cim] 0x%llx vptr=%s", (unsigned long long)cim, c1);
            dump_words(cim, 16, "cim");
            dump_vtable(img, cv, 12, "cim", 0);
        } else {
            RCL_LOGLN("[cim] 0x%llx has no vtable (+0x000 = %s, plain struct)",
                      (unsigned long long)cim, c1);
            dump_words(cim, 16, "cim");
        }
    }
}

static const int kGraphMax = 640;

struct GraphNode {
    uint64_t addr;
    uint64_t from;
    uint32_t off;
    uint8_t depth;
};

static void graph_walk(const Image &img, int snap, int depth, int maxnodes, int words) {
    if (depth < 1) depth = 1;
    if (depth > 6) depth = 6;
    if (maxnodes < 4) maxnodes = 4;
    if (maxnodes > kGraphMax) maxnodes = kGraphMax;
    if (words < 4) words = 4;
    if (words > 128) words = 128;

    static GraphNode q[kGraphMax];
    static uint64_t vts[24];
    int n = 0, nvt = 0;

    uint64_t home = 0, cur = 0, ga = 0, gb = 0;
    uint32_t state = 0;
    rd64(img.base + kHomeGlobal, home);
    rd64(img.base + kAuxGlobalA, ga);
    rd64(img.base + kAuxGlobalB, gb);
    if (home) {
        rd32(home + kHomeStateOff, state);
        rd64(home + kHomeCurrentOff, cur);
    }

    auto push = [&](uint64_t a, uint64_t from, uint32_t off, int d) {
        if (!plausible_ptr(img, a)) return;
        for (int i = 0; i < n; i++)
            if (q[i].addr == a) return;
        if (n >= maxnodes) return;
        q[n].addr = a;
        q[n].from = from;
        q[n].off = off;
        q[n].depth = (uint8_t)d;
        n++;
    };

    push(home, 0, 0, 0);
    push(cur, home, (uint32_t)kHomeCurrentOff, 0);
    push(ga, 0, 0, 0);
    push(gb, 0, 0, 0);

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
        if (obj && nvt < 24) {
            bool seen = false;
            for (int z = 0; z < nvt; z++)
                if (vts[z] == vt) seen = true;
            if (!seen) vts[nvt++] = vt;
        }
    }

    for (int z = 0; z < nvt; z++) {
        dump_vtable(img, vts[z], 32, "gvt", 0);
        dump_getters(img, vts[z], 8, 31, "gvt");
    }
    RCL_LOGLN("[graph] nodes=%d of max %d, distinct object vtables=%d", n, maxnodes, nvt);
}

void live_dump(const Image &img, const Seeds &s, int snap) {
    (void)s;
    uint64_t home = 0, ga = 0, gb = 0;
    rd64(img.base + kHomeGlobal, home);
    rd64(img.base + kAuxGlobalA, ga);
    rd64(img.base + kAuxGlobalB, gb);

    uint32_t state = 0;
    uint64_t cur = 0;
    if (home) {
        rd32(home + kHomeStateOff, state);
        rd64(home + kHomeCurrentOff, cur);
    }

    RCL_LOGLN("");
    RCL_LOGLN("[live #%d] home=0x%llx state=%u current=0x%llx auxA=0x%llx auxB=0x%llx", snap,
              (unsigned long long)home, state, (unsigned long long)cur, (unsigned long long)ga,
              (unsigned long long)gb);
    RCL_LOGLN("[chain] home=*(BASE+0x1123e58) state=home+0x50 current=home+0x48 mgr=current+0x28 inputMgr=current+0x58 arr=mgr+0x0 cap=mgr+0x8 count=mgr+0xc");
    if (!home) {
        RCL_LOGLN("[live #%d] home singleton null", snap);
        return;
    }

    dump_words(home, 24, "home");
    uint64_t hv = 0;
    rd64(home, hv);
    dump_vtable(img, hv, 32, "home", 0);

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

    int objcap = 96, fullmax = 24;
    const char *e = getenv("RCL_OBJ_MAX");
    if (e && *e) objcap = atoi(e);
    e = getenv("RCL_OBJ_FULL");
    if (e && *e) fullmax = atoi(e);
    if (objcap < 1) objcap = 1;
    if (objcap > 256) objcap = 256;
    if (fullmax < 1) fullmax = 1;
    if (fullmax > objcap) fullmax = objcap;

    dump_client(img, cur, "cur", objcap, fullmax, hv);

    int gdepth = 4, gmax = 256, gwords = 24;
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
    if (graph && (state == 5 || gany)) graph_walk(img, snap, gdepth, gmax, gwords);
}

void live_session(const Image &img, const Seeds &s) {
    int ticks = 600, ms = 2000, maxsnap = 16, battle_every = 5;
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
    if (maxsnap > 64) maxsnap = 64;
    if (battle_every < 1) battle_every = 1;
    if (battle_every > 1000) battle_every = 1000;

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
        rd64(img.base + kHomeGlobal, home);
        if (home) {
            rd32(home + kHomeStateOff, state);
            rd64(home + kHomeCurrentOff, cur);
            if (state < 32) seen |= (1u << state);
        }
        bool ok = false;
        if (cur) {
            rd64(cur + kClientMgrOff, mgr);
            ok = manager_ok(img, mgr, marr, n);
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
            RCL_LOGLN("[tick %3d t=%6.1fs] home singleton null", t, (t * ms                      ) / 1000.0);

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
