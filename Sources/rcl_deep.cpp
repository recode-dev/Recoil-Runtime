#include "rcl_deep.h"
#include "rcl_docdata.h"
#include "rcl_log.h"
#include "rcl_names.h"

#include <algorithm>
#include <dlfcn.h>
#include <glob.h>
#include <map>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <mach/mach.h>
#elif defined(RCL_HOST_TEST)
extern "C" const char *_dyld_get_image_name(unsigned int);
#endif

namespace rcl {

namespace {

bool d_rd(const Image &img, uint64_t va, void *dst, size_t n) {
    return img.read && img.read(img.ctx, va, dst, n);
}

bool d_rd32(const Image &img, uint64_t va, uint32_t &o) { return d_rd(img, va, &o, 4); }
bool d_rd64(const Image &img, uint64_t va, uint64_t &o) { return d_rd(img, va, &o, 8); }

bool d_cstr(const Image &img, uint64_t va, std::string &out) {
    out.clear();
    char buf[160];
    for (int i = 0; i < 160; i += 32) {
        size_t n = (size_t)(160 - i < 32 ? 160 - i : 32);
        if (!d_rd(img, va + (uint64_t)i, buf, n)) return false;
        for (size_t k = 0; k < n; k++) {
            char c = buf[k];
            if (!c) return out.size() >= 1;
            unsigned char u = (unsigned char)c;
            if (u < 32 || u > 126) return false;
            out.push_back(c);
            if (out.size() >= 128) return true;
        }
    }
    return false;
}

bool is_ident(const char *s) {
    if (!s || !*s) return false;
    const size_t n = strlen(s);
    if (n < 3 || n > 48) return false;
    unsigned char c0 = (unsigned char)s[0];
    if (!((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z') || c0 == '_')) return false;
    for (size_t i = 1; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '_')
            continue;
        return false;
    }
    return true;
}

uint64_t fnv1a(const void *p, size_t n, uint64_t h = 0xcbf29ce484222325ULL) {
    const uint8_t *b = (const uint8_t *)p;
    for (size_t i = 0; i < n; i++) {
        h ^= b[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

bool builtin_of(char c, const char *&out) {
    switch (c) {
        case 'v': out = "void"; return true;
        case 'b': out = "bool"; return true;
        case 'c': out = "char"; return true;
        case 'a': out = "signed char"; return true;
        case 'h': out = "unsigned char"; return true;
        case 's': out = "short"; return true;
        case 't': out = "unsigned short"; return true;
        case 'i': out = "int"; return true;
        case 'j': out = "unsigned int"; return true;
        case 'l': out = "long"; return true;
        case 'm': out = "unsigned long"; return true;
        case 'x': out = "long long"; return true;
        case 'y': out = "unsigned long long"; return true;
        case 'f': out = "float"; return true;
        case 'd': out = "double"; return true;
        case 'e': out = "long double"; return true;
        case 'w': out = "wchar_t"; return true;
        case 'z': out = "..."; return true;
        case 'u': out = "unsigned __int128"; return true;
        case 'n': out = "decltype(nullptr)"; return true;
        default: return false;
    }
}

const char *op_name(const char *p, int &len) {
    struct Op { const char *c; const char *n; };
    static const Op ops[] = {
        {"nw", "operator new"},   {"na", "operator new[]"}, {"dl", "operator delete"},
        {"da", "operator delete[]"}, {"ps", "operator+"},   {"ng", "operator-"},
        {"ad", "operator&"},      {"de", "operator*"},      {"co", "operator~"},
        {"pl", "operator+"},      {"mi", "operator-"},      {"ml", "operator*"},
        {"dv", "operator/"},      {"rm", "operator%"},      {"an", "operator&"},
        {"or", "operator|"},      {"eo", "operator^"},      {"aS", "operator="},
        {"pL", "operator+="},     {"mI", "operator-="},     {"mL", "operator*="},
        {"dV", "operator/="},     {"rM", "operator%="},     {"aN", "operator&="},
        {"oR", "operator|="},     {"eO", "operator^="},     {"ls", "operator<<"},
        {"rs", "operator>>"},     {"lS", "operator<<="},    {"rS", "operator>>="},
        {"eq", "operator=="},     {"ne", "operator!="},     {"lt", "operator<"},
        {"gt", "operator>"},      {"le", "operator<="},     {"ge", "operator>="},
        {"nt", "operator!"},      {"aa", "operator&&"},     {"oo", "operator||"},
        {"pp", "operator++"},     {"mm", "operator--"},     {"cm", "operator,"},
        {"pm", "operator->*"},    {"pt", "operator->"},     {"cl", "operator()"},
        {"ix", "operator[]"},     {"qu", "operator?"},      {"cv", "operator const"},
    };
    for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++) {
        if (p[0] == ops[i].c[0] && p[1] == ops[i].c[1]) {
            len = 2;
            return ops[i].n;
        }
    }
    return nullptr;
}

struct Dem {
    const char *p;
    const char *end;
    std::string out;
    std::vector<std::string> subs;
    int depth = 0;
    bool bad = false;

    bool eof() const { return p >= end || !*p; }

    bool digits(size_t &v) {
        if (eof() || !(*p >= '0' && *p <= '9')) return false;
        size_t n = 0;
        while (!eof() && *p >= '0' && *p <= '9' && n < 1000000) {
            n = n * 10 + (size_t)(*p - '0');
            p++;
        }
        if (*p == '_') p++;
        v = n;
        return true;
    }

    void add_sub(const std::string &s) {
        if (subs.size() < 4096 && !s.empty()) subs.push_back(s);
    }

    bool subst(std::string &out) {
        if (eof() || *p != 'S') return false;
        p++;
        if (eof()) { bad = true; return false; }
        if (*p == 't') {
            p++;
            if (!eof() && *p == 'd') { p++; out = "std::"; add_sub("std"); return true; }
            out = "std";
            add_sub("std");
            return true;
        }
        size_t idx = 0;
        if (*p == '_') {
            idx = 0;
            p++;
        } else {
            idx = 1;
            while (!eof() && *p != '_') {
                if (*p >= '0' && *p <= '9') idx = idx * 36 + (size_t)(*p - '0');
                else if (*p >= 'A' && *p <= 'Z') idx = idx * 36 + (size_t)(*p - 'A') + 10;
                else { bad = true; return false; }
                p++;
                if (idx > 4095) { bad = true; return false; }
            }
            if (eof()) { bad = true; return false; }
            p++;
        }
        size_t slot = idx ? idx - 1 : 0;
        if (slot >= subs.size()) { bad = true; return false; }
        out = subs[slot];
        return true;
    }

    bool targ(std::string &out) {
        if (eof()) { bad = true; return false; }
        if (*p == 'L') {
            p++;
            std::string lit;
            while (!eof() && *p != 'E') lit.push_back(*p++);
            if (eof()) { bad = true; return false; }
            p++;
            out = lit;
            return true;
        }
        if (*p == 'X') {
            p++;
            std::string t;
            if (!type(t)) return false;
            out = "decltype(" + t + ")";
            return true;
        }
        size_t save = subs.size();
        if (!type(out)) return false;
        while (subs.size() > save) subs.pop_back();
        return true;
    }

    bool targs(std::string &out) {
        p++;
        out.clear();
        int n = 0;
        for (;;) {
            if (eof()) { bad = true; return false; }
            if (*p == 'E') { p++; break; }
            std::string a;
            if (!targ(a)) return false;
            if (n) out += ", ";
            out += a;
            n++;
            if (n > 16) { bad = true; return false; }
        }
        return true;
    }

    bool source_name(std::string &out) {
        size_t n = 0;
        if (!digits(n)) return false;
        if (n == 0 || n > 256 || p + n > end) { bad = true; return false; }
        out.assign(p, n);
        p += n;
        if (!eof() && *p == 'I') {
            std::string args;
            if (!targs(args)) return false;
            out += args.empty() ? "<>" : "<" + args + ">";
        }
        return true;
    }

    bool name(std::string &out) {
        if (depth > 32) { bad = true; return false; }
        if (eof()) { bad = true; return false; }
        if (*p == 'S') return subst(out);
        if (*p == 'N') {
            p++;
            std::string acc;
            bool first = true;
            while (!eof() && *p != 'E') {
                char c = *p;
                if (c == 'K' || c == 'V' || c == 'r') { p++; continue; }
                std::string part;
                if ((c == 'C' || c == 'D') && p + 1 < end &&
                    (p[1] >= '0' && p[1] <= '9')) {
                    const char cls = c;
                    p += 2;
                    size_t cut = acc.rfind("::");
                    std::string owner = cut == std::string::npos ? acc : acc.substr(0, cut);
                    std::string last = cut == std::string::npos ? acc : acc.substr(cut + 2);
                    const size_t lt = last.find('<');
                    if (lt != std::string::npos) last = last.substr(0, lt);
                    part = last + (cls == 'C' ? "::" : "::~") + last;
                    if (owner.empty()) {
                        acc = part;
                    } else if (owner.size() + part.size() > 1 && part.compare(0, owner.size(), owner) == 0)
                        acc = part;
                    else
                        acc += "::" + part;
                } else if ((c >= '0' && c <= '9')) {
                    if (!source_name(part)) { bad = true; return false; }
                    if (first) acc = part;
                    else acc += "::" + part;
                } else if (c == 'S') {
                    if (!subst(part)) { bad = true; return false; }
                    if (first) acc = part;
                    else acc += "::" + part;
                } else {
                    int l = 0;
                    const char *on = op_name(p, l);
                    if (on) {
                        p += l;
                        part = on;
                        if (first) acc = part;
                        else acc += "::" + part;
                    } else if (c == 'L') {
                        p++;
                        std::string lit;
                        while (!eof() && *p != 'E') lit.push_back(*p++);
                        if (eof()) { bad = true; return false; }
                        p++;
                        part = lit;
                        if (first) acc = part;
                        else acc += "::" + part;
                    } else {
                        bad = true;
                        return false;
                    }
                }
                add_sub(part);
                first = false;
                if (acc.size() > 400) { bad = true; return false; }
            }
            if (eof()) { bad = true; return false; }
            p++;
            out = acc;
            return !out.empty();
        }
        std::string part;
        if (*p >= '0' && *p <= '9') {
            if (!source_name(part)) return false;
        } else {
            int l = 0;
            const char *on = op_name(p, l);
            if (!on) { bad = true; return false; }
            p += l;
            part = on;
        }
        add_sub(part);
        out = part;
        return true;
    }

    bool type(std::string &out) {
        if (depth > 32) { bad = true; return false; }
        if (eof()) { bad = true; return false; }
        char c = *p;
        const char *bn = nullptr;
        if (builtin_of(c, bn)) {
            p++;
            out = bn;
            return true;
        }
        if (c == 'P') { p++; std::string t; if (!type(t)) return false; out = t + "*"; return true; }
        if (c == 'R') { p++; std::string t; if (!type(t)) return false; out = t + "&"; return true; }
        if (c == 'O') { p++; std::string t; if (!type(t)) return false; out = t + "&&"; return true; }
        if (c == 'K') { p++; std::string t; if (!type(t)) return false; out = t + " const"; return true; }
        if (c == 'V') { p++; std::string t; if (!type(t)) return false; out = t + " volatile"; return true; }
        if (c == 'S' || c == 'N' || (c >= '0' && c <= '9')) {
            std::string t;
            if (!name(t)) return false;
            add_sub(t);
            out = t;
            return true;
        }
        bad = true;
        return false;
    }

    bool parse() {
        if (end - p < 3 || p[0] != '_' || p[1] != 'Z') return false;
        p += 2;
        if (!eof() && (*p == 'K' || *p == 'V' || *p == 'r')) p++;
        std::string nm;
        if (!name(nm)) return false;
        out = nm;
        if (eof()) return true;
        std::string params;
        int n = 0;
        while (!eof()) {
            std::string t;
            if (!type(t)) break;
            if (n) params += ", ";
            params += t;
            n++;
            if (n > 24) break;
        }
        if (n) out += "(" + params + ")";
        return !bad && !out.empty();
    }
};

const char *cxa_demangle_fn() { return "__cxa_demangle"; }

typedef char *(*cxa_demangle_t)(const char *, char *, size_t *, int *);

bool demangle_cxa(const char *m, std::string &out) {
    static cxa_demangle_t fn = nullptr;
    static int tried = 0;
    if (!tried) {
        tried = 1;
        fn = (cxa_demangle_t)dlsym(RTLD_DEFAULT, cxa_demangle_fn());
    }
    if (!fn) return false;
    int status = -1;
    char *r = fn(m, nullptr, nullptr, &status);
    if (status != 0 || !r) {
        if (r) free(r);
        return false;
    }
    out.assign(r);
    free(r);
    return !out.empty();
}

}

bool demangle_itanium(const char *m, std::string &out) {
    out.clear();
    if (!m || !*m) return false;
    const size_t n = strlen(m);
    if (n < 6 || n > 1024) return false;
    if (demangle_cxa(m, out)) return !out.empty();
    Dem d;
    d.p = m;
    d.end = m + n;
    if (!d.parse()) return false;
    out = d.out;
    return out.find("::") != std::string::npos;
}

const char *deep_ref_class(uint32_t vt) {
    for (uint32_t i = 0; i < kDocClassCount; i++)
        if (kDocClasses[i].vt == vt) return kDocBlob + kDocClasses[i].name;
    return "-";
}

namespace {

int64_t sx(uint32_t v, int bits) {
    const uint64_t m = 1ULL << (bits - 1);
    return (int64_t)((v ^ m) - m);
}

const std::vector<std::string> &ref_names_sorted() {
    static std::vector<std::string> v;
    if (v.empty()) {
        for (uint32_t i = 0; i < kDocClassCount; i++) v.push_back(kDocBlob + kDocClasses[i].name);
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }
    return v;
}

void mkpath(const char *p) {
    char buf[512];
    snprintf(buf, sizeof buf, "%s", p);
    for (char *q = buf + 1; *q; q++) {
        if (*q != '/') continue;
        *q = 0;
        mkdir(buf, 0755);
        *q = '/';
    }
    mkdir(buf, 0755);
}

struct TextBuf {
    std::vector<uint8_t> b;
    uint64_t lo = 0;
    uint64_t hi = 0;
    bool ok = false;
};

TextBuf &text_buf_get(const Image &img, const MachInsight &mi) {
    static TextBuf tb;
    if (tb.ok && tb.lo == mi.text_lo && tb.hi == mi.text_hi) return tb;
    tb = TextBuf();
    if (!mi.text_vmsize || mi.text_vmsize > (64u << 20)) return tb;
    tb.b.resize((size_t)mi.text_vmsize);
    uint64_t got = 0;
    const uint64_t chunk = 1u << 20;
    while (got < mi.text_vmsize) {
        uint64_t left = mi.text_vmsize - got;
        size_t n = (size_t)(left < chunk ? left : chunk);
        if (!d_rd(img, mi.text_lo + got, &tb.b[(size_t)got], n)) {
            tb.b.clear();
            return tb;
        }
        got += n;
    }
    tb.lo = mi.text_lo;
    tb.hi = mi.text_hi;
    tb.ok = true;
    return tb;
}

inline uint32_t tb_word(const TextBuf &tb, uint64_t va) {
    uint32_t w = 0;
    memcpy(&w, &tb.b[(size_t)(va - tb.lo)], 4);
    return w;
}

bool adrp_calc(uint32_t w, uint64_t va, uint64_t &page, uint32_t &rd) {
    if ((w & 0x9F000000u) != 0x90000000u && (w & 0x9F000000u) != 0x10000000u) return false;
    uint64_t imm = (((w >> 5) & 0x7FFFFu) << 2) | ((w >> 29) & 3u);
    page = (va & ~0xFFFULL) + ((uint64_t)sx((uint32_t)imm, 21) << 12);
    rd = w & 0x1Fu;
    return true;
}

bool add_same(uint32_t w, uint32_t rd, uint64_t page, uint64_t &out) {
    if ((w & 0x7F000000u) != 0x11000000u) return false;
    if (((w >> 5) & 0x1Fu) != rd) return false;
    if ((w & 0x1Fu) != rd) return false;
    out = page + (uint64_t)((w >> 10) & 0xFFFu);
    return true;
}

uint64_t img_slot(const Image &img, const MachInsight &mi, uint64_t slot, bool *ok) {
    uint64_t raw = 0;
    if (ok) *ok = false;
    if (!d_rd64(img, slot, raw)) return 0;
    int how = 0;
    uint64_t v = macho_slot_value(img, mi, raw, &how);
    if (!v) return 0;
    if (ok) *ok = true;
    return v;
}

uint32_t objc_ro_name(const Image &img, const MachInsight &mi, uint64_t class_va, uint64_t &ro_out) {
    ro_out = 0;
    bool ok = false;
    uint64_t bits = img_slot(img, mi, class_va + 40, &ok);
    if (!ok) return 0;
    uint64_t ro = bits & ~7ULL;
    if (!va_inside_image(mi, ro)) return 0;
    ro_out = ro;
    bool ok2 = false;
    uint64_t name = img_slot(img, mi, ro + 24, &ok2);
    if (!ok2) return 0;
    return (uint32_t)(name - img.base);
}

void objc_dump_methods(const Image &img, const MachInsight &mi, FILE *f, uint64_t ro, uint32_t cap,
                       uint32_t &counted) {
    bool ok = false;
    uint64_t ml = img_slot(img, mi, ro + 32, &ok);
    if (!ok) return;
    uint32_t ef = 0, cnt = 0;
    if (!d_rd32(img, ml, ef) || !d_rd32(img, ml + 4, cnt)) return;
    if (!cnt || cnt > 4096) return;
    const bool rel = (ef & 0x3u) == 0x3u;
    uint32_t esz = ef & ~0x3u;
    if (esz < 8 || esz > 64) esz = rel ? 12u : 24u;
    for (uint32_t i = 0; i < cnt; i++) {
        const uint64_t ent = ml + 8 + (uint64_t)i * esz;
        uint64_t nva = 0;
        if (rel) {
            uint32_t off = 0;
            if (!d_rd32(img, ent, off)) break;
            nva = ent + (uint64_t)(int64_t)(int32_t)off;
        } else {
            bool ok2 = false;
            nva = img_slot(img, mi, ent, &ok2);
            if (!ok2) break;
        }
        if (!va_inside_image(mi, nva)) continue;
        std::string sel;
        if (!d_cstr(img, nva, sel)) continue;
        counted++;
        if (counted <= cap)
            fprintf(f, "| `%#x` | `+%u` | %s |\n", (uint32_t)(ent - img.base), i * esz, sel.c_str());
    }
}

#if defined(__APPLE__) || defined(RCL_HOST_TEST)
typedef char *(*swift_demangle_t)(const char *, size_t, char *, size_t *, uint32_t);

std::string swift_name(const std::string &raw) {
    static swift_demangle_t fn = nullptr;
    static int tried = 0;
    if (!tried) {
        tried = 1;
        fn = (swift_demangle_t)dlsym(RTLD_DEFAULT, "swift_demangle");
    }
    if (!fn) return raw;
    char out[512];
    size_t cap = sizeof out - 1;
    char *r = fn(raw.c_str(), raw.size(), out, &cap, 0);
    if (!r) return raw;
    const size_t n = strlen(r);
    if (!n || n > 400) return raw;
    return std::string(r, n);
}
#endif

const char *const kCsvDirs[] = {"assets/logic", "logic", "assets", "Documents/logic",
                                "Documents/sc/logic"};

}

void deep_macho_report(const Image &img, const MachInsight &mi, const FnStarts &fs,
                        const std::vector<SecRange> &dic, const char *root, DeepStats &st) {
    (void)img;
    char path[1024];
    snprintf(path, sizeof path, "%s/_macho.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# what the loader and the runtime say about this image\n\n");
    fprintf(f, "| field | value |\n|-------|-------|\n");
    fprintf(f, "| ncmds | %u |\n", mi.ncmds);
    fprintf(f, "| cputype / subtype | %u / %u%s |\n", mi.cputype, mi.cpusubtype,
            mi.is_arm64e ? " (arm64e)" : "");
    fprintf(f, "| filetype | %u |\n", mi.filetype);
    fprintf(f, "| flags | `%#x` |\n", mi.flags);
    fprintf(f, "| uuid | `%s` |\n", mi.uuid[0] ? mi.uuid : "-");
    fprintf(f, "| build version | %s |\n", build_version_text(mi).c_str());
    fprintf(f, "| __TEXT vmaddr / vmsize | `%#llx` / `%#llx` |\n", (unsigned long long)mi.text_vmaddr,
            (unsigned long long)mi.text_vmsize);
    fprintf(f, "| slide | `%#llx` |\n", (unsigned long long)mi.slide);
    fprintf(f, "| image range | `%#llx`..`%#llx` |\n", (unsigned long long)mi.image_lo,
            (unsigned long long)mi.image_hi);
    fprintf(f, "| segments / sections | %zu / %zu |\n", mi.segs.size(), mi.sections.size());
    fprintf(f, "\n## loader features\n\n");
    fprintf(f, "| feature | present | used as |\n|---------|---------|---------|\n");
    fprintf(f, "| `LC_FUNCTION_STARTS` | %s | %s |\n", mi.has_function_starts ? "yes" : "no",
            "exact function starts, tier 1");
    fprintf(f, "| `__unwind_info` | %s | %s |\n", mi.has_unwind_info ? "yes" : "no",
            "function starts fallback, tier 2");
    fprintf(f, "| `LC_DATA_IN_CODE` | %s | in-text data excluded from slots |\n",
            mi.has_data_in_code ? "yes" : "no");
    fprintf(f, "| `LC_DYLD_CHAINED_FIXUPS` | %s | pointer format %u |\n",
            mi.has_chained_fixups ? "yes" : "no", (unsigned)mi.pointer_format);
    fprintf(f, "| `LC_SYMTAB` | %s | %s |\n", mi.has_symtab ? "yes" : "no",
            mi.has_symtab ? "symbols present" : "stripped");
    fprintf(f, "| `LC_DYLD_EXPORTS_TRIE` | %s | - |\n", mi.has_exports_trie ? "yes" : "no");
    const char *src = st.fstarts_source == 1 ? "LC_FUNCTION_STARTS"
                      : st.fstarts_source == 2 ? "__unwind_info"
                                              : "boundary scan, tier 3";
    fprintf(f, "\n## function starts\n\n");
    fprintf(f, "- source: **%s**\n", src);
    fprintf(f, "- starts recovered: **%u**\n", st.fstarts);
    fprintf(f, "- candidates rejected during the scan: %u\n", st.fstarts_rejected);
    fprintf(f, "- exact set, a slot must equal a start: %s\n", fs.exact ? "yes" : "no");
    fprintf(f, "- in-text data ranges excluded: %u\n", st.data_in_code);
    for (size_t i = 0; i < dic.size() && i < 40; i++)
        fprintf(f, "- in-text data `%s` `%#llx`..`%#llx`\n", dic[i].sect,
                (unsigned long long)dic[i].start, (unsigned long long)dic[i].end);
    fclose(f);
    RCL_LOGLN("[deep] macho: fstarts=%u source=%d exact=%d uuid=%s", st.fstarts, st.fstarts_source,
              fs.exact ? 1 : 0, mi.uuid[0] ? mi.uuid : "-");
}

void deep_objc(const Image &img, const MachInsight &mi, const char *root, DeepStats &st) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_objc.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# ObjC and Swift metadata\n\n");

    std::vector<SecRange> cls, cats, selrefs, methnames, swt;
    sections_named(mi, "__objc_classlist", cls);
    sections_named(mi, "__objc_catlist", cats);
    sections_named(mi, "__objc_selrefs", selrefs);
    sections_named(mi, "__objc_methname", methnames);
    sections_named(mi, "__swift5_types", swt);

    fprintf(f, "| section | ranges |\n|---------|--------|\n");
    fprintf(f, "| `__objc_classlist` | %zu |\n", cls.size());
    fprintf(f, "| `__objc_catlist` | %zu |\n", cats.size());
    fprintf(f, "| `__objc_selrefs` | %zu |\n", selrefs.size());
    fprintf(f, "| `__objc_methname` | %zu |\n", methnames.size());
    fprintf(f, "| `__swift5_types` | %zu |\n", swt.size());

    for (size_t r = 0; r < methnames.size(); r++) {
        uint64_t va = methnames[r].start;
        uint64_t guard = 0;
        while (va < methnames[r].end && guard < (1u << 20)) {
            std::string s;
            if (!d_cstr(img, va, s)) {
                va += 1;
                guard++;
                continue;
            }
            st.objc_methnames++;
            va += s.size() + 1;
            guard += s.size() + 1;
        }
    }

    for (size_t r = 0; r < selrefs.size(); r++) {
        for (uint64_t va = selrefs[r].start; va + 8 <= selrefs[r].end; va += 8) {
            bool ok = false;
            uint64_t s = img_slot(img, mi, va, &ok);
            if (!ok) continue;
            std::string sel;
            if (!d_cstr(img, s, sel)) continue;
            st.objc_selrefs++;
        }
    }

    fprintf(f, "\n## classes\n\n");
    bool header = false;
    for (size_t r = 0; r < cls.size(); r++) {
        for (uint64_t va = cls[r].start; va + 8 <= cls[r].end; va += 8) {
            bool ok = false;
            uint64_t class_va = img_slot(img, mi, va, &ok);
            if (!ok) continue;
            uint64_t ro = 0;
            uint32_t nro = objc_ro_name(img, mi, class_va, ro);
            if (!nro) continue;
            std::string cname;
            if (!d_cstr(img, img.base + nro, cname)) continue;
            std::string sup = "-";
            bool oks = false;
            uint64_t sup_va = img_slot(img, mi, class_va + 8, &oks);
            if (oks) {
                uint64_t sro = 0;
                uint32_t snro = objc_ro_name(img, mi, sup_va, sro);
                std::string sn;
                if (snro && d_cstr(img, img.base + snro, sn)) sup = sn;
            }
            if (!header) {
                fprintf(f, "| class | class va | ro | superclass | methods |\n");
                fprintf(f, "|-------|----------|----|------------|---------|\n");
                header = true;
            }
            const uint32_t before = st.objc_methods;
            std::vector<std::string> sels;
            st.objc_classes++;
            fprintf(f, "\n### %s\n\n", cname.c_str());
            fprintf(f, "`class` `%#llx`  `ro` `%#llx`  super `%s`\n\n", (unsigned long long)class_va,
                    (unsigned long long)ro, sup.c_str());
            fprintf(f, "| method rva | slot | selector |\n|------------|------|----------|\n");
            objc_dump_methods(img, mi, f, ro, 64, st.objc_methods);
            fprintf(f, "\nmethods: %u\n", st.objc_methods - before);
        }
    }

    for (size_t r = 0; r < cats.size(); r++) {
        for (uint64_t va = cats[r].start; va + 8 <= cats[r].end; va += 8) {
            bool ok = false;
            img_slot(img, mi, va, &ok);
            if (!ok) continue;
            st.objc_cats++;
        }
    }

#if defined(__APPLE__) || defined(RCL_HOST_TEST)
    if (!swt.empty()) fprintf(f, "\n## swift types\n");
    for (size_t r = 0; r < swt.size(); r++) {
        for (uint64_t va = swt[r].start; va + 4 <= swt[r].end; va += 4) {
            uint32_t off = 0;
            if (!d_rd32(img, va, off)) break;
            uint64_t desc = va + (uint64_t)(int64_t)(int32_t)off;
            if (!va_inside_image(mi, desc)) continue;
            uint64_t namef = desc + 8;
            uint32_t noff = 0;
            if (!d_rd32(img, namef, noff)) continue;
            uint64_t nva = namef + (uint64_t)(int64_t)(int32_t)noff;
            if (!va_inside_image(mi, nva)) continue;
            std::string raw;
            if (!d_cstr(img, nva, raw)) continue;
            st.swift_types++;
            if (st.swift_types <= 200)
                fprintf(f, "- `%#x` `%s`\n", (uint32_t)(desc - img.base),
                        swift_name(raw).c_str());
        }
    }
#endif

    fprintf(f, "\n## counts\n\n");
    fprintf(f, "| item | count |\n|------|-------|\n");
    fprintf(f, "| classes | %u |\n", st.objc_classes);
    fprintf(f, "| methods | %u |\n", st.objc_methods);
    fprintf(f, "| categories | %u |\n", st.objc_cats);
    fprintf(f, "| methname strings | %u |\n", st.objc_methnames);
    fprintf(f, "| selrefs resolved | %u |\n", st.objc_selrefs);
    fprintf(f, "| swift types | %u |\n", st.swift_types);
    fclose(f);
    RCL_LOGLN("[deep] objc: classes=%u methods=%u selrefs=%u methnames=%u cats=%u swift=%u",
              st.objc_classes, st.objc_methods, st.objc_selrefs, st.objc_methnames, st.objc_cats,
              st.swift_types);
}

void deep_mangled(const Image &img, const MachInsight &mi, const char *root, DeepStats &st) {
    std::vector<SecRange> ranges;
    sections_named(mi, "__cstring", ranges);

    std::map<std::string, std::vector<std::string>> by_class;
    std::vector<uint8_t> buf(1u << 16);
    std::string carry;

    for (size_t r = 0; r < ranges.size(); r++) {
        uint64_t va = ranges[r].start;
        carry.clear();
        while (va < ranges[r].end) {
            const uint64_t left = ranges[r].end - va;
            const size_t want = (size_t)(left < buf.size() ? left : buf.size());
            if (!d_rd(img, va, &buf[0], want)) break;
            size_t i = 0;
            while (i < want) {
                const uint8_t c = buf[i];
                if (c == 0) {
                    if (carry.size() >= 6 && carry.size() <= 512 && carry[0] == '_' &&
                        carry[1] == 'Z') {
                        std::string dem;
                        if (demangle_itanium(carry.c_str(), dem)) {
                            st.mangled_found++;
                            const size_t cut = dem.rfind("::");
                            const std::string cls =
                                cut == std::string::npos ? dem : dem.substr(0, cut);
                            if (by_class[cls].size() < 64) by_class[cls].push_back(dem);
                        }
                    }
                    carry.clear();
                    i++;
                    continue;
                }
                if (c < 32 || c > 126) {
                    carry.clear();
                    i++;
                    continue;
                }
                if (carry.size() < 520) carry.push_back((char)c);
                i++;
            }
            va += want;
        }
    }
    st.mangled_classes = (uint32_t)by_class.size();

    char path[1024];
    snprintf(path, sizeof path, "%s/_mangled.md", root);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "# C++ names recovered from this build's own strings\n\n");
        fprintf(f, "recovered %u names in %u classes, no reference table used\n\n", st.mangled_found,
                st.mangled_classes);
        uint32_t shown = 0;
        for (std::map<std::string, std::vector<std::string>>::const_iterator it = by_class.begin();
             it != by_class.end() && shown < 1000; ++it, ++shown) {
            fprintf(f, "## %s  (%zu)\n\n", it->first.c_str(), it->second.size());
            for (size_t k = 0; k < it->second.size() && k < 24; k++)
                fprintf(f, "- `%s`\n", it->second[k].c_str());
            fprintf(f, "\n");
        }
        fclose(f);
    }
    RCL_LOGLN("[deep] mangled: names=%u classes=%u", st.mangled_found, st.mangled_classes);
}

void deep_fieldmap(const Image &img, const MachInsight &mi, const FnStarts &fs, const char *root,
                   DeepStats &st) {
    const TextBuf &tb = text_buf_get(img, mi);
    if (!tb.ok) return;

    struct Pair {
        std::string prop;
        uint32_t off;
        uint8_t width;
        uint32_t loader;
    };
    std::vector<Pair> pairs;
    std::map<uint32_t, uint32_t> per_loader;
    const uint64_t n = mi.text_vmsize / 4;
    for (uint64_t i = 0; i + 2 < n && pairs.size() < 400000; i++) {
        const uint64_t va = tb.lo + i * 4;
        uint64_t page = 0;
        uint32_t rd = 0;
        if (!adrp_calc(tb_word(tb, va), va, page, rd)) continue;
        uint64_t full = 0;
        if (!add_same(tb_word(tb, va + 4), rd, page, full)) continue;
        if (!va_inside_image(mi, full)) continue;
        std::string s;
        if (!d_cstr(img, full, s)) continue;
        if (!is_ident(s.c_str())) continue;

        bool saw_bl = false;
        for (int k = 2; k < 26; k++) {
            const uint32_t w = tb_word(tb, va + (uint64_t)k * 4);
            if ((w & 0xFC000000u) == 0x94000000u) {
                saw_bl = true;
                continue;
            }
            if (!saw_bl) continue;
            uint32_t off = 0;
            uint8_t width = 0;
            const uint32_t op = w & 0xFFC00000u;
            if (op == 0xB9000000u && (w & 0x1Fu) < 31u) {
                off = ((w >> 10) & 0xFFFu) * 4u;
                width = 4;
            } else if (op == 0xF9000000u && (w & 0x1Fu) < 31u) {
                off = ((w >> 10) & 0xFFFu) * 8u;
                width = 8;
            } else if (op == 0x39000000u && (w & 0x1Fu) < 31u) {
                off = (w >> 10) & 0xFFFu;
                width = 1;
            } else if ((w & 0xFFE00C00u) == 0xB8000000u && (w & 0x1Fu) < 31u) {
                off = (uint32_t)sx((w >> 12) & 0x1FFu, 9) * 4u;
                width = 4;
            } else if ((w & 0xFFE00C00u) == 0x38000000u && (w & 0x1Fu) < 31u) {
                off = (uint32_t)sx((w >> 12) & 0x1FFu, 9);
                width = 1;
            } else {
                continue;
            }
            if (off > 0x200000u) continue;
            const uint32_t loader = fs.fn_at((uint32_t)(va - img.base));
            Pair p;
            p.prop = s;
            p.off = off;
            p.width = width;
            p.loader = loader;
            pairs.push_back(p);
            per_loader[loader]++;
            break;
        }
    }
    st.field_pairs = (uint32_t)pairs.size();
    st.loaders = (uint32_t)per_loader.size();

    char path[1024];
    snprintf(path, sizeof path, "%s/_fieldmap.tsv", root);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "loader_rva\tproperty\toffset\twidth\tclass\n");
        for (size_t i = 0; i < pairs.size(); i++)
            fprintf(f, "%#x\t%s\t%u\t%u\t%s\n", pairs[i].loader, pairs[i].prop.c_str(),
                    pairs[i].off, (unsigned)pairs[i].width, deep_ref_class(pairs[i].loader));
        fclose(f);
    }

    snprintf(path, sizeof path, "%s/_fieldmap.md", root);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "# property to field offset, read off this build's own code\n\n");
        fprintf(f, "loaders %u | pairs %u\n\n", st.loaders, st.field_pairs);
        fprintf(f, "| loader rva | class | properties |\n|------------|-------|------------|\n");
        uint32_t shown = 0;
        for (std::map<uint32_t, uint32_t>::const_iterator it = per_loader.begin();
             it != per_loader.end() && shown < 400; ++it, ++shown)
            fprintf(f, "| `%#x` | %s | %u |\n", it->first, deep_ref_class(it->first), it->second);
        fprintf(f, "\n## lookup\n\n");
        fprintf(f, "| property | loader rva | offset | width |\n|----------|-----------|--------|-------|\n");
        for (size_t i = 0; i < pairs.size(); i++)
            fprintf(f, "| `%s` | `%#x` | `%#x` | %u |\n", pairs[i].prop.c_str(), pairs[i].loader,
                    pairs[i].off, (unsigned)pairs[i].width);
        fclose(f);
    }
    RCL_LOGLN("[deep] fieldmap: loaders=%u pairs=%u", st.loaders, st.field_pairs);
}

void deep_accessors(const Image &img, const MachInsight &mi, const FnStarts &fs,
                    const std::vector<ClassTable> &tables, const char *root, DeepStats &st) {
    const TextBuf &tb = text_buf_get(img, mi);
    if (!tb.ok || tb.b.size() < 64) return;

    struct Acc {
        uint32_t rva;
        uint32_t off;
        uint32_t owner;
        uint32_t size;
        uint8_t width;
        uint8_t kind;
    };
    std::vector<Acc> acc;
    acc.reserve(16384);

    const uint64_t n = mi.text_vmsize / 4;
    for (uint64_t i = 0; i + 4 < n; i++) {
        const uint64_t va = tb.lo + i * 4;
        const uint32_t w = tb_word(tb, va);
        if (((w >> 5) & 0x1Fu) != 0u) continue;
        const uint32_t rt = w & 0x1Fu;
        const uint32_t m12 = w & 0xFFC00000u;
        uint32_t off = 0;
        uint8_t width = 0;
        uint8_t kind = 0;
        if (m12 == 0xF9400000u && rt == 0) {
            off = ((w >> 10) & 0xFFFu) * 8u; width = 8; kind = 1;
        } else if (m12 == 0xB9400000u && rt == 0) {
            off = ((w >> 10) & 0xFFFu) * 4u; width = 4; kind = 1;
        } else if (m12 == 0x39400000u && rt == 0) {
            off = (w >> 10) & 0xFFFu; width = 1; kind = 1;
        } else if (m12 == 0x79400000u && rt == 0) {
            off = ((w >> 10) & 0xFFFu) * 2u; width = 2; kind = 1;
        } else if (m12 == 0xFD400000u && rt == 0) {
            off = ((w >> 10) & 0xFFFu) * 8u; width = 8; kind = 2;
        } else if (m12 == 0xBD400000u && rt == 0) {
            off = ((w >> 10) & 0xFFFu) * 4u; width = 4; kind = 2;
        } else if (m12 == 0xB9800000u && rt == 0) {
            off = ((w >> 10) & 0xFFFu) * 4u; width = 4; kind = 3;
        } else if (m12 == 0xF9000000u) {
            off = ((w >> 10) & 0xFFFu) * 8u; width = 8; kind = 4;
        } else if (m12 == 0xB9000000u) {
            off = ((w >> 10) & 0xFFFu) * 4u; width = 4; kind = 4;
        } else if (m12 == 0x39000000u) {
            off = (w >> 10) & 0xFFFu; width = 1; kind = 4;
        } else if (m12 == 0x79000000u) {
            off = ((w >> 10) & 0xFFFu) * 2u; width = 2; kind = 4;
        } else if (m12 == 0xFD000000u) {
            off = ((w >> 10) & 0xFFFu) * 8u; width = 8; kind = 5;
        } else if (m12 == 0xBD000000u) {
            off = ((w >> 10) & 0xFFFu) * 4u; width = 4; kind = 5;
        } else {
            continue;
        }
        if (off > 0x100000u) continue;

        uint32_t tail = 0;
        const uint32_t b = tb_word(tb, va + 4);
        if (b == 0xD65F03C0u) {
            tail = 8;
        } else {
            const uint32_t sh = b & 0x7F800000u;
            if (sh != 0x53000000u && sh != 0x13000000u) continue;
            if (tb_word(tb, va + 8) == 0xD65F03C0u) {
                tail = 12;
            } else {
                const uint32_t sh2 = tb_word(tb, va + 8) & 0x7F800000u;
                if ((sh2 != 0x53000000u && sh2 != 0x13000000u) ||
                    tb_word(tb, va + 12) != 0xD65F03C0u)
                    continue;
                tail = 16;
            }
        }
        Acc a;
        a.rva = (uint32_t)(va - img.base);
        a.off = off;
        a.owner = 0;
        a.size = tail;
        a.width = width;
        a.kind = kind;
        acc.push_back(a);
    }

    std::map<uint32_t, uint32_t> slot_owner;
    for (size_t i = 0; i < tables.size(); i++) {
        const ClassTable &t = tables[i];
        for (uint32_t s = 0; s < t.slots; s++) {
            uint64_t raw = 0;
            if (!d_rd(img, img.base + t.start + (uint64_t)s * 8, &raw, 8)) break;
            int how = 0;
            const uint64_t v = macho_slot_value(img, mi, raw, &how);
            if (!v) continue;
            const uint32_t r = (uint32_t)(v - img.base);
            if (!slot_owner.count(r)) slot_owner[r] = t.start;
        }
    }
    for (size_t i = 0; i < acc.size(); i++) {
        std::map<uint32_t, uint32_t>::const_iterator it = slot_owner.find(acc[i].rva);
        if (it != slot_owner.end()) acc[i].owner = it->second;
    }

    st.accessors = (uint32_t)acc.size();
    for (size_t i = 0; i < acc.size(); i++) {
        if (acc[i].kind <= 3) st.getters++;
        else st.setters++;
        if (acc[i].owner) st.accessors_owned++;
    }

    static const char *kKind[] = {"", "load", "load-fp", "load-sx", "store", "store-fp"};

    char path[1024];
    snprintf(path, sizeof path, "%s/_accessors.tsv", root);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "rva\tclass\tkind\toffset\twidth\tsize\tat_function_start\n");
        for (size_t i = 0; i < acc.size(); i++) {
            const Acc &a = acc[i];
            fprintf(f, "%#x\t%s\t%s\t%u\t%u\t%u\t%d\n", a.rva,
                    a.owner ? deep_ref_class(a.owner) : "-", kKind[a.kind], a.off,
                    (unsigned)a.width, a.size, fs.is_start(a.rva) ? 1 : 0);
        }
        fclose(f);
    }

    snprintf(path, sizeof path, "%s/_getters.md", root);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "# leaf getters, found by disassembling this image's own __text\n\n");
        fprintf(f, "A getter is the whole function: `ldr Rd,[x0,#imm]` then `ret` "
                   "(one or two shifts allowed).\nThe class comes from the class table that "
                   "holds this function in a slot; `-` means the function is not virtual.\n\n");
        fprintf(f, "getters %u | with a class %u | setters %u | all accessors %u\n\n",
                st.getters, st.accessors_owned, st.setters, st.accessors);
        fprintf(f, "| rva | class | field | width | shape | at start |\n");
        fprintf(f, "|-----|-------|-------|-------|-------|----------|\n");
        for (size_t i = 0; i < acc.size(); i++) {
            const Acc &a = acc[i];
            if (a.kind > 3) continue;
            fprintf(f, "| `%#x` | %s | `+%#x` | %u | %s | %d |\n", a.rva,
                    a.owner ? deep_ref_class(a.owner) : "-", a.off, (unsigned)a.width,
                    kKind[a.kind], fs.is_start(a.rva) ? 1 : 0);
        }
        fclose(f);
    }

    snprintf(path, sizeof path, "%s/_setters.md", root);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "# leaf setters, found by disassembling this image's own __text\n\n");
        fprintf(f, "setters %u | all accessors %u\n\n", st.setters, st.accessors);
        fprintf(f, "| rva | class | field | width | shape |\n|-----|-------|-------|-------|-------|\n");
        for (size_t i = 0; i < acc.size(); i++) {
            const Acc &a = acc[i];
            if (a.kind <= 3) continue;
            fprintf(f, "| `%#x` | %s | `+%#x` | %u | %s |\n", a.rva,
                    a.owner ? deep_ref_class(a.owner) : "-", a.off, (unsigned)a.width,
                    kKind[a.kind]);
        }
        fclose(f);
    }
    RCL_LOGLN("[deep] accessors: getters=%u setters=%u with_class=%u", st.getters, st.setters,
              st.accessors_owned);
}

void deep_functions(const Image &img, const MachInsight &mi, const FnStarts &fs,
                    const std::vector<ClassTable> &tables, const char *root, DeepStats &st) {
    const TextBuf &tb = text_buf_get(img, mi);
    if (!tb.ok || fs.v.empty()) return;

    std::map<uint32_t, std::string> tab_cls;
    for (size_t i = 0; i < tables.size(); i++) {
        const char *n = deep_ref_class(tables[i].start);
        if (n && n[0]) tab_cls[tables[i].start] = n;
    }

    st.func_total = (uint32_t)fs.v.size();

    char path[1024];
    snprintf(path, sizeof path, "%s/_functions.tsv", root);
    FILE *f = fopen(path, "w");
    if (f) fprintf(f, "rva\tsize\tkind\tdetail\tstrings\tcalls\twhole\n");

    for (size_t i = 0; i < fs.v.size(); i++) {
        const uint32_t rva = fs.v[i];
        const uint32_t size = fs.size_of(rva);
        if (!size || size > 0x10000u) continue;
        const uint32_t insns = size / 4;
        const char *kind = "code";
        std::string detail;
        uint32_t nstr = 0;
        uint32_t ncalls = 0;

        for (uint32_t k = 0; k < insns && k < 48u; k++) {
            const uint64_t va = tb.lo + (uint64_t)rva + (uint64_t)k * 4;
            const uint32_t w = tb_word(tb, va);
            if ((w & 0xFC000000u) == 0x94000000u) {
                ncalls++;
                continue;
            }
            uint64_t page = 0;
            uint32_t rd = 0;
            if (!adrp_calc(w, va, page, rd)) continue;
            uint64_t full = 0;
            if (!add_same(tb_word(tb, va + 4), rd, page, full)) continue;
            const uint32_t trva = (uint32_t)(full - img.base);
            std::map<uint32_t, std::string>::const_iterator it = tab_cls.find(trva);
            if (it != tab_cls.end()) {
                const uint32_t w3 = tb_word(tb, va + 8);
                if ((w3 & 0xFFC00000u) == 0xF9000000u && ((w3 >> 5) & 0x1Fu) == 0u &&
                    (w3 & 0x1Fu) == rd && ((w3 >> 10) & 0xFFFu) == 0u) {
                    kind = "ctor";
                    detail = it->second;
                    st.func_ctor++;
                }
                continue;
            }
            if (nstr < 3u) {
                std::string s;
                if (d_cstr(img, full, s) && s.size() >= 3u && s.size() <= 120u) nstr++;
            }
        }
        if (f) {
            fprintf(f, "%#x\t%u\t%s\t%s\t%u\t%u\t%d\n", rva, size, kind,
                    detail.empty() ? "-" : detail.c_str(), nstr, ncalls, fs.is_start(rva) ? 1 : 0);
        }
    }
    if (f) fclose(f);
    RCL_LOGLN("[deep] functions: total=%u ctor=%u", st.func_total, st.func_ctor);
}

void deep_indirect(const Image &img, const MachInsight &mi, const FnStarts &fs,
                   std::vector<ClassTable> &extra, DeepStats &st) {
    const TextBuf &tb = text_buf_get(img, mi);
    if (!tb.ok) return;
    std::map<uint64_t, uint32_t> base_calls;
    const uint64_t n = mi.text_vmsize / 4;
    for (uint64_t i = 0; i + 18 < n; i++) {
        const uint64_t va = tb.lo + i * 4;
        uint64_t page = 0;
        uint32_t rd = 0;
        if (!adrp_calc(tb_word(tb, va), va, page, rd)) continue;
        uint64_t base = 0;
        if (!add_same(tb_word(tb, va + 4), rd, page, base)) continue;
        if (!va_inside_image(mi, base)) continue;
        for (int k = 2; k < 18; k++) {
            const uint32_t w = tb_word(tb, va + (uint64_t)k * 4);
            const bool idx_ldr = (w & 0xFFE00C00u) == 0xF8600800u && ((w >> 5) & 0x1Fu) == rd;
            const bool off_ldr = (w & 0xFFC00000u) == 0xF9400000u && ((w >> 5) & 0x1Fu) == rd &&
                                 (((w >> 10) & 0xFFFu) % 8u) == 0u;
            if (idx_ldr || off_ldr) {
                base_calls[base]++;
                st.indirect_calls++;
                break;
            }
        }
    }
    st.indirect_bases = (uint32_t)base_calls.size();
    for (std::map<uint64_t, uint32_t>::const_iterator it = base_calls.begin();
         it != base_calls.end(); it++) {
        const uint64_t base = it->first;
        uint32_t slots = 0;
        for (uint32_t s = 0; s < 512; s++) {
            bool ok = false;
            uint64_t v = img_slot(img, mi, base + (uint64_t)s * 8, &ok);
            if (!ok) break;
            if (v < mi.text_lo || v >= mi.text_hi) break;
            if (fs.exact && !fs.is_start((uint32_t)(v - img.base))) break;
            slots++;
        }
        if (slots < 2) continue;
        ClassTable t;
        t.start = (uint32_t)(base - img.base);
        t.slots = slots;
        t.seg = "indirect";
        extra.push_back(t);
        st.indirect_added++;
    }
    std::sort(extra.begin(), extra.end(),
              [](const ClassTable &a, const ClassTable &b) { return a.start < b.start; });
    RCL_LOGLN("[deep] indirect: bases=%u calls=%u tables=%u", st.indirect_bases, st.indirect_calls,
              st.indirect_added);
}

void deep_logic(const char *root, DeepStats &st) {
    std::string base;
    const char *env = getenv("RCL_APP_DIR");
    if (env && *env) base = env;
#if defined(__APPLE__) || defined(RCL_HOST_TEST)
    if (base.empty()) {
        const char *p0 = _dyld_get_image_name(0);
        if (p0 && *p0) {
            std::string s(p0);
            const size_t app = s.find(".app/");
            if (app != std::string::npos) base = s.substr(0, app + 4);
            else {
                const size_t slash = s.rfind('/');
                if (slash != std::string::npos) base = s.substr(0, slash);
            }
        }
    }
#endif
    char path[1024];
    snprintf(path, sizeof path, "%s/_logic_classes.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# logic data tables shipped with this build\n\n");
    fprintf(f, "searched under `%s`\n\n", base.empty() ? "(unknown app dir)" : base.c_str());
    if (base.empty()) {
        fprintf(f, "no app directory, set `RCL_APP_DIR` to enable this stage\n");
        fclose(f);
        return;
    }
    fprintf(f,
            "| file | class | columns | first columns |\n|------|-------|---------|---------------|\n");
    for (size_t d = 0; d < sizeof kCsvDirs / sizeof kCsvDirs[0] && !st.logic_files; d++) {
        char pat[1200];
        snprintf(pat, sizeof pat, "%s/%s/*.csv", base.c_str(), kCsvDirs[d]);
        glob_t g;
        memset(&g, 0, sizeof g);
        if (glob(pat, 0, nullptr, &g) != 0) continue;
        for (size_t k = 0; k < g.gl_pathc; k++) {
            const char *file = g.gl_pathv[k];
            FILE *c = fopen(file, "r");
            if (!c) continue;
            char line[8192];
            const bool got = fgets(line, sizeof line, c) != nullptr;
            fclose(c);
            if (!got) continue;
            size_t ln = strlen(line);
            while (ln && (line[ln - 1] == '\n' || line[ln - 1] == '\r')) line[--ln] = 0;
            std::vector<std::string> cols;
            std::string cur;
            for (size_t i = 0; i <= ln; i++) {
                if (i == ln || line[i] == ',') {
                    cols.push_back(cur);
                    cur.clear();
                } else {
                    cur.push_back(line[i]);
                }
            }
            const char *bn = strrchr(file, '/');
            bn = bn ? bn + 1 : file;
            std::string cls(bn);
            const size_t dot = cls.rfind('.');
            if (dot != std::string::npos) cls = cls.substr(0, dot);
            st.logic_files++;
            st.logic_fields += (uint32_t)cols.size();
            std::string head;
            for (size_t i = 0; i < cols.size() && i < 6; i++) {
                if (i) head += ", ";
                head += cols[i];
            }
            fprintf(f, "| `%s` | `%s` | %zu | %s |\n", bn, cls.c_str(), cols.size(), head.c_str());
        }
        globfree(&g);
    }
    fclose(f);
    RCL_LOGLN("[deep] logic assets: files=%u fields=%u", st.logic_files, st.logic_fields);
}

#if defined(__APPLE__) || defined(RCL_HOST_TEST)

extern "C" unsigned int mach_task_self_;
extern "C" int mach_vm_read_overwrite(unsigned int, unsigned long long, unsigned long long,
                                      unsigned long long, unsigned long long *);
extern "C" int mach_vm_region(unsigned int, unsigned long long *, unsigned long long *, int, void *,
                              unsigned int *, unsigned int *);

struct VmRegionBasic64 {
    unsigned int protection;
    unsigned int max_protection;
    unsigned int inheritance;
    unsigned int shared;
    unsigned int reserved;
    unsigned int pad;
    unsigned long long offset;
    unsigned int behavior;
    unsigned int user_wired_count;
};

void deep_heap(const Image &img, const MachInsight &mi, const FnStarts &fs, const char *root,
               DeepStats &st) {
    std::map<uint32_t, uint32_t> hits;
    uint64_t addr = 0x100000000ULL;
    uint32_t regions = 0;
    uint64_t words = 0;
    const uint64_t max_words = 8u << 20;
    const unsigned int kBasicInfo64 = 9;
    const unsigned int kProtWrite = 2;
    const unsigned int kProtExec = 4;
    while (addr < 0x8000000000ULL && regions < 4000 && words < max_words) {
        unsigned long long sz = 0;
        VmRegionBasic64 info;
        memset(&info, 0, sizeof info);
        unsigned int cnt = (unsigned int)(sizeof info / sizeof(unsigned int));
        unsigned int obj = 0;
        unsigned long long q = addr;
        if (mach_vm_region(mach_task_self_, &q, &sz, (int)kBasicInfo64, &info, &cnt, &obj) != 0) break;
        const uint64_t rsz = sz;
        const uint64_t next = addr + (rsz ? rsz : 0x1000);
        if (!(info.protection & kProtWrite) || (info.protection & kProtExec)) {
            addr = next;
            continue;
        }
        bool inside_image = false;
        for (size_t i = 0; i < mi.segs.size(); i++) {
            const uint64_t lo = mi.segs[i].vmaddr + mi.slide;
            if (addr + rsz > lo && addr < lo + mi.segs[i].vmsize) {
                inside_image = true;
                break;
            }
        }
        if (inside_image) {
            addr = next;
            continue;
        }
        regions++;
        const uint64_t cap = rsz > (8u << 20) ? (8u << 20) : rsz;
        for (uint64_t off = 0; off + 8 <= cap && words < max_words; off += 8) {
            uint64_t raw = 0;
            unsigned long long got = 0;
            if (mach_vm_read_overwrite(mach_task_self_, addr + off, 8, (unsigned long long)&raw, &got) !=
                    0 ||
                got != 8)
                continue;
            words++;
            if (!raw) continue;
            int how = 0;
            uint64_t v = macho_slot_value(img, mi, raw, &how);
            if (!v) continue;
            bool ok = false;
            uint64_t first = img_slot(img, mi, v, &ok);
            if (!ok) continue;
            if (first < mi.text_lo || first >= mi.text_hi) continue;
            if (fs.exact && !fs.is_start((uint32_t)(first - img.base))) continue;
            hits[(uint32_t)(v - img.base)]++;
        }
        addr = next;
    }
    st.heap_regions = regions;
    st.heap_words = words;
    st.heap_vptrs = (uint32_t)hits.size();

    char path[1024];
    snprintf(path, sizeof path, "%s/_live_vtables.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# tables that were live in memory during this run\n\n");
    fprintf(f, "regions %u | words %llu | distinct vptr %u\n\n", regions, (unsigned long long)words,
            st.heap_vptrs);
    fprintf(f,
            "| table rva | objects seen | slots | class |\n|-----------|--------------|-------|-------|\n");
    for (std::map<uint32_t, uint32_t>::const_iterator it = hits.begin(); it != hits.end(); it++) {
        uint32_t slots = 0;
        for (uint32_t s = 0; s < 512; s++) {
            bool ok = false;
            img_slot(img, mi, img.base + it->first + (uint64_t)s * 8, &ok);
            if (!ok) break;
            slots++;
        }
        if (!slots) continue;
        st.heap_tables++;
        fprintf(f, "| `%#x` | %u | %u | %s |\n", it->first, it->second, slots,
                deep_ref_class(it->first));
    }
    fclose(f);
    RCL_LOGLN("[deep] heap: regions=%u words=%llu vptrs=%u tables=%u", st.heap_regions,
              (unsigned long long)st.heap_words, st.heap_vptrs, st.heap_tables);
}

#else

void deep_heap(const Image &, const MachInsight &, const FnStarts &, const char *root,
               DeepStats &st) {
    (void)st;
    char path[1024];
    snprintf(path, sizeof path, "%s/_live_vtables.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# tables that were live in memory during this run\n\n");
    fprintf(f, "the heap walk needs the device; nothing recorded in this run\n");
    fclose(f);
}

#endif

void deep_order(const Image &img, const MachInsight &mi, const std::vector<ClassTable> &tables,
                const std::map<uint32_t, std::string> &named, const char *root,
                std::map<uint32_t, std::string> &out, DeepStats &st) {
    const std::vector<std::string> &all = ref_names_sorted();
    std::vector<uint32_t> unnamed;
    std::vector<std::pair<uint32_t, std::string>> anchors;
    for (size_t i = 0; i < tables.size(); i++) {
        std::map<uint32_t, std::string>::const_iterator it = named.find(tables[i].start);
        const char *rn = deep_ref_class(tables[i].start);
        std::string have;
        if (it != named.end()) have = it->second;
        else if (strcmp(rn, "-") != 0) have = rn;
        if (have.empty()) {
            unnamed.push_back(tables[i].start);
            continue;
        }
        const size_t cut = have.find("::");
        if (cut != std::string::npos) have = have.substr(0, cut);
        if (!have.empty() && have[0] == '~') have = have.substr(1);
        anchors.push_back(std::make_pair(tables[i].start, have));
    }

    char path[1024];
    snprintf(path, sizeof path, "%s/_order_fill.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# unnamed tables whose alphabet range holds exactly one reference class\n\n");
    fprintf(f, "| table rva | before | after | candidates | name |\n");
    fprintf(f, "|-----------|--------|-------|------------|------|\n");

    for (size_t i = 0; i < unnamed.size(); i++) {
        const uint32_t target = unnamed[i];
        std::string before, after;
        for (size_t k = 0; k < anchors.size(); k++) {
            if (anchors[k].first < target) {
                before = anchors[k].second;
                continue;
            }
            after = anchors[k].second;
            break;
        }
        if (before.empty() || after.empty() || before >= after) continue;
        st.order_pairs++;
        std::vector<std::string> in;
        for (size_t k = 0; k < all.size(); k++)
            if (all[k] > before && all[k] < after) in.push_back(all[k]);
        if (in.size() != 1) {
            fprintf(f, "| `%#x` | %s | %s | %zu | - |\n", target, before.c_str(), after.c_str(),
                    in.size());
            continue;
        }
        fprintf(f, "| `%#x` | %s | %s | 1 | %s |\n", target, before.c_str(), after.c_str(),
                in[0].c_str());
        if (!out.count(target)) {
            out[target] = in[0];
            st.order_named++;
        }
    }
    fclose(f);
    RCL_LOGLN("[deep] order: pairs=%u named=%u", st.order_pairs, st.order_named);
    (void)img;
    (void)mi;
}

void deep_fingerprints(const Image &img, const MachInsight &mi, const FnStarts &fs,
                       const std::vector<ClassTable> &tables,
                       const std::map<uint32_t, std::string> &named, const char *root,
                       std::map<uint32_t, std::string> &carried, DeepStats &st) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_fingerprints.tsv", root);
    char prev[1200];
    snprintf(prev, sizeof prev, "%s/_fingerprints.prev.tsv", root);

    std::map<uint64_t, std::string> old_by_fp;
    FILE *p = fopen(prev, "r");
    if (p) {
        char line[512];
        while (fgets(line, sizeof line, p)) {
            unsigned long long fp = 0;
            unsigned int slots = 0, rva = 0;
            char name[256];
            name[0] = 0;
            if (sscanf(line, "%llx\t%x\t%x\t%255s", &fp, &slots, &rva, name) == 4 && name[0] &&
                strcmp(name, "-") != 0)
                old_by_fp[fp] = name;
        }
        fclose(p);
    }

    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "fingerprint\tslots\trva\tclass\n");
    std::vector<uint8_t> bytes(16);
    for (size_t i = 0; i < tables.size(); i++) {
        const ClassTable &t = tables[i];
        uint64_t h = fnv1a(&t.slots, sizeof t.slots);
        for (uint32_t s = 0; s < t.slots && s < 64; s++) {
            bool ok = false;
            uint64_t v = img_slot(img, mi, img.base + t.start + (uint64_t)s * 8, &ok);
            if (!ok) continue;
            if (!d_rd(img, v, &bytes[0], bytes.size())) continue;
            h = fnv1a(&bytes[0], bytes.size(), h);
        }
        st.fp_written++;
        std::map<uint32_t, std::string>::const_iterator it = named.find(t.start);
        const char *rn = deep_ref_class(t.start);
        std::string have;
        if (it != named.end()) have = it->second;
        else if (strcmp(rn, "-") != 0) have = rn;
        if (!have.empty()) {
            fprintf(f, "%llx\t%x\t%x\t%s\n", (unsigned long long)h, t.slots, t.start, have.c_str());
            continue;
        }
        std::map<uint64_t, std::string>::const_iterator o = old_by_fp.find(h);
        if (o == old_by_fp.end()) {
            fprintf(f, "%llx\t%x\t%x\t-\n", (unsigned long long)h, t.slots, t.start);
            continue;
        }
        st.fp_matched++;
        if (!carried.count(t.start)) {
            carried[t.start] = o->second;
            st.fp_named++;
        }
        fprintf(f, "%llx\t%x\t%x\t%s\n", (unsigned long long)h, t.slots, t.start, o->second.c_str());
    }
    fclose(f);

    {
        FILE *src = fopen(path, "r");
        FILE *dst = fopen(prev, "w");
        if (src && dst) {
            char b[4096];
            size_t n = 0;
            while ((n = fread(b, 1, sizeof b, src)) > 0) fwrite(b, 1, n, dst);
        }
        if (dst) fclose(dst);
        if (src) fclose(src);
    }
    (void)fs;
    RCL_LOGLN("[deep] fingerprints: written=%u matched=%u named=%u", st.fp_written, st.fp_matched,
              st.fp_named);
}

void deep_cache_load(const char *root, const char *uuid, std::map<uint32_t, std::string> &names,
                     DeepStats &st) {
    if (!uuid || !*uuid) return;
    char path[1024];
    snprintf(path, sizeof path, "%s/cache", root);
    mkpath(path);
    snprintf(path, sizeof path, "%s/cache/%s.tsv", root, uuid);
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        unsigned int rva = 0;
        char name[256];
        name[0] = 0;
        if (sscanf(line, "%x\t%255s", &rva, name) == 2 && name[0]) {
            names[rva] = name;
            st.cache_names++;
        }
    }
    fclose(f);
    RCL_LOGLN("[deep] cache: %u names from %s", st.cache_names, path);
}

void deep_cache_save(const char *root, const char *uuid,
                     const std::map<uint32_t, std::string> &names) {
    if (!uuid || !*uuid || names.empty()) return;
    char path[1024];
    snprintf(path, sizeof path, "%s/cache", root);
    mkpath(path);
    snprintf(path, sizeof path, "%s/cache/%s.tsv", root, uuid);
    FILE *f = fopen(path, "w");
    if (!f) return;
    for (std::map<uint32_t, std::string>::const_iterator it = names.begin(); it != names.end(); ++it)
        fprintf(f, "%x\t%s\n", it->first, it->second.c_str());
    fclose(f);
}

void write_deep_summary(const MachInsight &mi, const char *root, const DeepStats &st) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_summary.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# Recoil dump - version independent coverage\n\n");
    fprintf(f, "image `%s`  %s\n\n", mi.uuid[0] ? mi.uuid : "-", build_version_text(mi).c_str());
    fprintf(f, "| stage | result | independent of build because |\n");
    fprintf(f, "|-------|--------|------------------------------|\n");
    fprintf(f, "| function starts | %u (%s) | loader ABI |\n", st.fstarts,
            st.fstarts_source == 1 ? "LC_FUNCTION_STARTS"
                                   : st.fstarts_source == 2 ? "__unwind_info" : "boundary scan");
    fprintf(f, "| in-text data excluded | %u | LC_DATA_IN_CODE |\n", st.data_in_code);
    fprintf(f, "| ObjC classes | %u | runtime metadata |\n", st.objc_classes);
    fprintf(f, "| ObjC methods | %u | runtime metadata |\n", st.objc_methods);
    fprintf(f, "| ObjC categories | %u | runtime metadata |\n", st.objc_cats);
    fprintf(f, "| ObjC selector refs | %u | runtime metadata |\n", st.objc_selrefs);
    fprintf(f, "| ObjC methname strings | %u | runtime metadata |\n", st.objc_methnames);
    fprintf(f, "| Swift types | %u | runtime metadata |\n", st.swift_types);
    fprintf(f, "| mangled names recovered | %u | text inside the binary |\n", st.mangled_found);
    fprintf(f, "| mangled classes | %u | text inside the binary |\n", st.mangled_classes);
    fprintf(f, "| property loaders | %u | property names in the binary |\n", st.loaders);
    fprintf(f, "| property to offset pairs | %u | property names in the binary |\n", st.field_pairs);
    fprintf(f, "| indirect-call bases | %u (%u calls) | compiler shape |\n", st.indirect_bases,
            st.indirect_calls);
    fprintf(f, "| tables added from indirect calls | %u | compiler shape |\n", st.indirect_added);
    fprintf(f, "| logic csv files | %u (%u columns) | shipped data |\n", st.logic_files,
            st.logic_fields);
    fprintf(f, "| live heap regions | %u (%llu words) | C++ object ABI |\n", st.heap_regions,
            (unsigned long long)st.heap_words);
    fprintf(f, "| live vptrs / tables | %u / %u | C++ object ABI |\n", st.heap_vptrs, st.heap_tables);
    fprintf(f, "| alphabet sandwiches | %u | linker order |\n", st.order_pairs);
    fprintf(f, "| names from alphabet | %u | linker order |\n", st.order_named);
    fprintf(f, "| fingerprints written | %u | code shape |\n", st.fp_written);
    fprintf(f, "| names carried by fingerprint | %u | code shape |\n", st.fp_named);
    fprintf(f, "| names from cache | %u | same image uuid |\n", st.cache_names);
    fprintf(f, "\n## acceptance rules used in this run\n\n");
    fprintf(f, "- a slot is accepted only when it equals a recovered function start\n");
    fprintf(f, "- a name comes only from the binary itself, from runtime metadata, from shipped\n"
               "  data, from linker order with a single candidate, from a byte-identical\n"
               "  fingerprint, or from the cache of the very same image uuid\n");
    fprintf(f, "- no reference addresses, CRCs or per-build constants are consulted\n");
    fclose(f);
}

}
