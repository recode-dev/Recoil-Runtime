#include "rcl_classdump.h"
#include "rcl_docdata.h"
#include "rcl_docgen.h"
#include "rcl_livedocs.h"
#include "rcl_log.h"
#include "rcl_names.h"
#include "rcl_live.h"
#include "rcl_deep.h"
#include "rcl_macho.h"
#include <algorithm>
#include <dirent.h>
#include <map>
#include <set>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace rcl {

#include "rcl_classdump.h"



namespace {

struct Mh {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct Lc {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct SegCmd {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t maxprot;
    int32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct Range {
    char name[17];
    uint64_t start;
    uint64_t end;
};

const uint32_t kLcSegment64 = 0x19;
const uint32_t kLcFunctionStarts = 0x26;
const uint32_t kRunMin = 2;
const uint32_t kLooseRunMin = 3;
const uint32_t kRunMax = 4096;
const uint32_t kStrMax = 1024;
const uint32_t kStrMin = 4;
const uint32_t kFnStrMax = 8;
const uint64_t kBlockGap = 0x400;
const uint32_t kBlockMinSeeds = 4;
const uint32_t kClusterSharedMin = 3;

extern "C" unsigned int mach_task_self_;
extern "C" int mach_vm_read_overwrite(unsigned int task, unsigned long long addr,
                                      unsigned long long size, unsigned long long dst,
                                      unsigned long long *outsize);

bool safe_read8(uint64_t va, uint64_t *out) {
    unsigned long long got = 0;
    if (!va || (va & 7)) return false;
    if (va < 0x100000000ULL || va > 0x800000000000ULL) return false;
    if (mach_vm_read_overwrite(mach_task_self_, va, 8, (unsigned long long)out, &got) != 0) return false;
    return got == 8;
}

bool at(const Image &img, uint64_t va, void *dst, size_t n) {
    return img.read && img.read(img.ctx, va, dst, n);
}

MachInsight g_insight;
FnStarts g_fnstarts;
std::vector<SecRange> g_datacode;
uint64_t g_insight_base = 0;
bool g_insight_done = false;

const MachInsight *g_mi = nullptr;
const FnStarts *g_fs = nullptr;
const std::vector<SecRange> *g_dic = nullptr;
std::vector<uint32_t> g_slot_starts;

void ensure_insight(const Image &img) {
    if (g_insight_done && g_insight_base == img.base) return;
    g_insight_base = img.base;
    g_insight_done = true;
    g_insight = MachInsight();
    g_fnstarts = FnStarts();
    g_datacode.clear();
    g_mi = nullptr;
    g_fs = nullptr;
    g_dic = nullptr;
    if (!macho_insight(img, g_insight)) return;
    fn_starts_build(img, g_insight, g_fnstarts);
    g_datacode = read_data_in_code(img, g_insight);
    g_mi = &g_insight;
    g_fs = &g_fnstarts;
    g_dic = &g_datacode;
}

int segments(const Image &img, Range *out, int cap) {
    Mh mh;
    int n = 0;
    if (!at(img, img.base, &mh, sizeof(mh))) return -1;
    if (mh.magic != 0xFEEDFACFu) return -1;
    uint64_t p = img.base + sizeof(Mh);
    for (uint32_t c = 0; c < mh.ncmds && n < cap; c++) {
        Lc lc;
        if (!at(img, p, &lc, sizeof(lc))) break;
        if (lc.cmdsize < sizeof(Lc) || lc.cmdsize > 0x10000) break;
        if (lc.cmd == kLcSegment64) {
            SegCmd sg;
            if (at(img, p, &sg, sizeof(sg))) {
                memcpy(out[n].name, sg.segname, 16);
                out[n].name[16] = 0;
                out[n].start = sg.vmaddr;
                out[n].end = sg.vmaddr + sg.vmsize;
                n++;
            }
        }
        p += lc.cmdsize;
    }
    return n;
}

bool loose_at(const Image &img, uint64_t raw, uint64_t tlo, uint64_t thi, uint32_t *rva) {
    uint64_t va = raw & 0xFFFFFFFFFULL;
    uint32_t w = 0;
    if (va < tlo || va >= thi) return false;
    if (!at(img, va, &w, sizeof(w))) return false;
    if (rva) *rva = (uint32_t)(va - img.base);
    return true;
}

bool entry(uint32_t w) {
    if (w == 0xD503233Fu || w == 0xD503237Fu || w == 0xD65F03C0u || w == 0xD503201Fu) return true;
    if ((w & 0xFFFFFF1Fu) == 0xD503241Fu) return true;
    if ((w & 0xFF800000u) == 0xA9800000u && ((w >> 5) & 31u) == 31u) return true;
    if ((w & 0xFF800000u) == 0xA9000000u && ((w >> 5) & 31u) == 31u) return true;
    if ((w & 0xFFC003FFu) == 0xD10003FFu) return true;
    if ((w & 0xFF8003FFu) == 0xD10003FFu) return true;
    if ((w & 0xFFFFFFE0u) == 0x910003E0u) return true;
    if ((w & 0xFFFFFC1Fu) == 0xD4200000u) return true;
    if ((w & 0xFC000000u) == 0x14000000u) return true;
    return false;
}

bool after_boundary(const Image &img, uint32_t rva) {
    uint32_t w = 0;
    if (rva < 4) return false;
    if (!at(img, img.base + rva - 4, &w, sizeof(w))) return false;
    return w == 0xD65F03C0u || (w & 0xFC000000u) == 0x14000000u || w == 0xD503201Fu;
}

bool slot_at(const Image &img, uint64_t raw, uint64_t tlo, uint64_t thi, uint32_t *rva,
             ScanStats *st) {
    ensure_insight(img);
    uint64_t va = g_mi ? macho_slot_value(img, *g_mi, raw, nullptr) : 0;
    if (!va) va = raw & 0xFFFFFFFFFULL;
    uint32_t w = 0;
    if (va < tlo || va >= thi) return false;
    if (st) st->ptr_ok++;
    if (!at(img, va, &w, sizeof(w))) return false;
    const uint32_t r = (uint32_t)(va - img.base);
    bool ok = entry(w) || after_boundary(img, r);
    if (!ok && g_fs) ok = g_fs->is_start(r);
    if (ok && g_dic && in_ranges(*g_dic, va)) ok = false;
    if (!ok) {
        if (st) {
            st->entry_rej++;
            if (!st->sample_reason) {
                st->sample_reason = 1;
                st->sample_raw = (uint32_t)(raw & 0xFFFFFFFF);
                st->sample_rva = r;
            }
        }
        return false;
    }
    if (st) st->entry_ok++;
    if (g_fs && !g_fs->is_start(r) && g_slot_starts.size() < (1u << 19))
        g_slot_starts.push_back(r);
    if (rva) *rva = r;
    return true;
}

const char *class_of(const char *name) {
    static char buf[96];
    const char *p = strstr(name, "::");
    size_t n = p ? (size_t)(p - name) : strlen(name);
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    memcpy(buf, name, n);
    buf[n] = 0;
    return buf;
}

struct Layout {
    uint32_t magic = 0;
    uint32_t ncmds = 0;
    uint64_t slide = 0;
    uint64_t code_lo = 0;
    uint64_t code_hi = 0;
    Range data[64];
    int data_n = 0;
    int hdr = 0;
    int nsegs = 0;
};

void layout(const Image &img, Layout &L) {
    Range segs[64];
    L.nsegs = segments(img, segs, 64);
    L.hdr = L.nsegs > 0;
    Mh mh;
    if (at(img, img.base, &mh, sizeof(mh))) {
        L.magic = mh.magic;
        L.ncmds = mh.ncmds;
    }
    for (int i = 0; i < L.nsegs; i++)
        if (strncmp(segs[i].name, "__TEXT", 16) == 0 && L.slide == 0 && img.base >= segs[i].start)
            L.slide = img.base - segs[i].start;
    for (int i = 0; i < L.nsegs; i++) {
        Range r = segs[i];
        r.start += L.slide;
        r.end += L.slide;
        if (strncmp(r.name, "__TEXT", 16) == 0) {
            L.code_lo = r.start;
            L.code_hi = r.end;
            continue;
        }
        if (strncmp(r.name, "__LINKEDIT", 16) == 0) continue;
        if (strncmp(r.name, "__PAGEZERO", 16) == 0) continue;
        if (L.data_n < 64) L.data[L.data_n++] = r;
    }
    if (L.data_n == 0) {
        Range r;
        snprintf(r.name, sizeof(r.name), "%s", "image");
        r.start = L.code_hi ? L.code_hi : img.base + 0xf74000;
        r.end = img.base + (img.image_vmsize ? img.image_vmsize : 0x1200000);
        L.data[L.data_n++] = r;
    }
    if (!L.code_lo) {
        L.code_lo = img.base;
        L.code_hi = img.base + (img.vmsize ? img.vmsize : 0xf74000);
    }
}

}  // namespace

std::vector<ClassTable> scan_loose(const Image &img, const Layout &L, ScanStats *st) {
    std::vector<ClassTable> out;
    for (int i = 0; i < L.data_n; i++) {
        uint64_t va = L.data[i].start;
        while (va + 8 <= L.data[i].end) {
            uint64_t raw = 0;
            if (st) st->loose_words++;
            if (!at(img, va, &raw, sizeof(raw))) break;
            if (!loose_at(img, raw, L.code_lo, L.code_hi, nullptr)) {
                va += 8;
                continue;
            }
            uint32_t n = 0;
            uint64_t p = va;
            while (p + 8 <= L.data[i].end && n < kRunMax) {
                uint64_t r2 = 0;
                if (!at(img, p, &r2, sizeof(r2))) break;
                if (!loose_at(img, r2, L.code_lo, L.code_hi, nullptr)) break;
                n++;
                p += 8;
            }
            if (n >= kLooseRunMin) {
                ClassTable t;
                t.start = (uint32_t)(va - img.base);
                t.slots = n;
                t.seg = L.data[i].name;
                for (uint32_t k = 0; k < n; k++) {
                    uint64_t r3 = 0;
                    uint32_t sr = 0;
                    if (!at(img, img.base + t.start + k * 8, &r3, sizeof(r3))) break;
                    if (!loose_at(img, r3, L.code_lo, L.code_hi, &sr)) continue;
                    if (name_for_rva(sr)[0] != '-') t.named++;
                }
                out.push_back(t);
            }
            va = p > va ? p : va + 8;
        }
    }
    std::sort(out.begin(), out.end(),
              [](const ClassTable &a, const ClassTable &b) { return a.start < b.start; });
    return out;
}

std::vector<ClassTable> scan_class_tables(const Image &img, ScanStats *st) {
    std::vector<ClassTable> out;
    Layout L;
    layout(img, L);
    if (st) {
        st->hdr_ok = L.hdr;
        st->magic = L.magic;
        st->ncmds = L.ncmds;
        st->slide = L.slide;
        st->segs.clear();
        for (int i = 0; i < L.data_n; i++) {
            SegInfo si;
            memcpy(si.name, L.data[i].name, sizeof(si.name));
            si.start = L.data[i].start;
            si.end = L.data[i].end;
            st->segs.push_back(si);
        }
    }
    for (int i = 0; i < L.data_n; i++) {
        uint64_t va = L.data[i].start;
        while (va + 8 <= L.data[i].end) {
            uint64_t raw = 0;
            if (st) st->words++;
            if (!at(img, va, &raw, sizeof(raw))) break;
            if (!slot_at(img, raw, L.code_lo, L.code_hi, nullptr, st)) {
                va += 8;
                continue;
            }
            uint32_t n = 0;
            uint64_t p = va;
            while (p + 8 <= L.data[i].end && n < kRunMax) {
                uint64_t r2 = 0;
                if (!at(img, p, &r2, sizeof(r2))) break;
                if (!slot_at(img, r2, L.code_lo, L.code_hi, nullptr, nullptr)) break;
                n++;
                p += 8;
            }
            if (n >= kRunMin) {
                ClassTable t;
                t.start = (uint32_t)(va - img.base);
                t.slots = n;
                t.seg = L.data[i].name;
                for (uint32_t s = 0; s < n; s++) {
                    uint64_t r3 = 0;
                    uint32_t sr = 0;
                    if (!at(img, img.base + t.start + s * 8, &r3, sizeof(r3))) break;
                    if (!slot_at(img, r3, L.code_lo, L.code_hi, &sr, nullptr)) continue;
                    if (name_for_rva(sr)[0] != '-') t.named++;
                }
                out.push_back(t);
            }
            va = p > va ? p : va + 8;
        }
    }
    std::sort(out.begin(), out.end(),
              [](const ClassTable &a, const ClassTable &b) { return a.start < b.start; });
    if (st) st->tables_strict = (uint32_t)out.size();
    if (out.empty()) {
        out = scan_loose(img, L, st);
        if (st) st->tables_loose = (uint32_t)out.size();
    }
    return out;
}


const char *dumps_root() {
    static char root[512];
    const char *e = getenv("RCL_DUMPS_DIR");
    const char *d = getenv("RCL_DOCS_DIR");
    const char *rp = getenv("RCL_REPORTS_DIR");
    const char *rd = getenv("RCL_LOG_DIR");
    const char *home = getenv("HOME");
    if (e && *e) snprintf(root, sizeof root, "%s", e);
    else if (d && *d) snprintf(root, sizeof root, "%s", d);
    else if (rp && *rp) snprintf(root, sizeof root, "%s", rp);
    else if (home && *home) snprintf(root, sizeof root, "%s/Documents/Dumps", home);
    else if (rd && *rd) snprintf(root, sizeof root, "%s/Dumps", rd);
    else snprintf(root, sizeof root, "%s", "/var/mobile/Documents/Dumps");
    if (root[0] != '/') return root;
    for (char *p = root + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        mkdir(root, 0755);
        *p = '/';
    }
    mkdir(root, 0755);
    return root;
}

namespace {

const char *dump_root() { return dumps_root(); }

const char *diag_root() { return dumps_root(); }

struct LiveArg {
    Image img;
};

void *live_main(void *arg) {
    LiveArg *a = (LiveArg *)arg;
    int tick = 0;
    for (;;) {
        sleep(2);
        uint32_t state = 0;
        uint64_t home = 0, cur = 0;
        live_home(a->img, home, state, cur);
        live_docs_note(a->img, state, ++tick);
    }
    return nullptr;
}

void live_boot(const Image &img) {
    static bool started = false;
    if (started) return;
    started = true;
    {
        uint64_t h = 0, c = 0;
        uint32_t st = 0;
        live_home(img, h, st, c);
    }
    LiveArg *a = new LiveArg();
    a->img = img;
    pthread_t th;
    if (pthread_create(&th, nullptr, live_main, a) == 0) pthread_detach(th);
}

}  // namespace

namespace {

struct StrEnt {
    uint32_t va;
    uint32_t len;
};

std::vector<uint32_t> build_starts(const Image &img, const Layout &L) {
    std::vector<uint32_t> out;
    uint32_t prev = 0;
    for (uint64_t va = L.code_lo; va + 4 <= L.code_hi; va += 4) {
        uint32_t w = 0;
        if (!at(img, va, &w, 4)) break;
        if (prev == 0xD65F03C0u || (prev & 0xFC000000u) == 0x14000000u || prev == 0xD503201Fu)
            if (entry(w)) out.push_back((uint32_t)(va - img.base));
        prev = w;
    }
    std::sort(out.begin(), out.end());
    return out;
}

uint32_t fn_of(const std::vector<uint32_t> &starts, uint32_t rva, bool *exact) {
    uint32_t lo = 0, hi = (uint32_t)starts.size();
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        if (starts[mid] <= rva) lo = mid + 1;
        else hi = mid;
    }
    if (!lo) {
        if (exact) *exact = false;
        return 0;
    }
    if (exact) *exact = (starts[lo - 1] == rva);
    return starts[lo - 1];
}

bool byte_text(uint8_t c) { return c >= 32 && c <= 126; }

uint32_t text_len(const Image &img, uint64_t va, uint64_t hi, uint32_t cap) {
    uint32_t n = 0;
    while (va + n < hi && n < cap) {
        uint8_t c = 0;
        if (!at(img, va + n, &c, 1)) break;
        if (!byte_text(c)) break;
        n++;
    }
    return n;
}

std::vector<StrEnt> build_strings(const Image &img, const Layout &L) {
    std::vector<StrEnt> out;
    const uint64_t lo = L.code_lo;
    const uint64_t hi = L.code_hi;
    for (uint64_t va = lo; va + 1 <= hi; ) {
        uint8_t c = 0;
        if (!at(img, va, &c, 1)) break;
        if (!byte_text(c)) {
            va += 1;
            continue;
        }
        uint32_t len = text_len(img, va, hi, kStrMax);
        if (len >= kStrMin) out.push_back({(uint32_t)(va - img.base), len});
        if (out.size() > 400000) break;
        va += len + 1;
    }
    std::sort(out.begin(), out.end(), [](const StrEnt &a, const StrEnt &b) { return a.va < b.va; });
    return out;
}

const StrEnt *find_str(const std::vector<StrEnt> &s, uint32_t va) {
    uint32_t lo = 0, hi = (uint32_t)s.size();
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        if (s[mid].va == va) return &s[mid];
        if (s[mid].va < va) lo = mid + 1;
        else hi = mid;
    }
    return nullptr;
}

bool read_str(const Image &img, const StrEnt &e, char *dst, size_t cap) {
    size_t n = e.len < cap - 1 ? e.len : cap - 1;
    if (!at(img, img.base + e.va, dst, n)) return false;
    dst[n] = 0;
    return true;
}

std::map<std::string, std::string> g_unique_str;

void build_unique_strings() {
    std::map<std::string, int> cnt;
    std::map<std::string, std::string> who;
    for (uint32_t c = 0; c < kDocClassCount; c++) {
        const char *p = kDocBlob + kDocClasses[c].strings;
        while (p && *p) {
            const char *e = strchr(p, '\x1f');
            size_t n = e ? (size_t)(e - p) : strlen(p);
            std::string s(p, n);
            cnt[s]++;
            who[s] = kDocBlob + kDocClasses[c].name;
            if (!e) break;
            p = e + 1;
        }
    }
    for (std::map<std::string, int>::iterator it = cnt.begin(); it != cnt.end(); ++it)
        if (it->second == 1) g_unique_str[it->first] = who[it->first];
}

bool class_specific_string(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || s[0] == '%') return false;
    if (n >= 16) return g_unique_str.find(std::string(s)) != g_unique_str.end();
    if (strstr(s, "::")) return true;
    return false;
}

const char *ref_class_for_string(const char *s) {
    for (uint32_t c = 0; c < kDocClassCount; c++) {
        const char *p = kDocBlob + kDocClasses[c].strings;
        while (p && *p) {
            const char *e = strchr(p, '\x1f');
            size_t n = e ? (size_t)(e - p) : strlen(p);
            if (n == strlen(s) && strncmp(p, s, n) == 0) return kDocBlob + kDocClasses[c].name;
            if (!e) break;
            p = e + 1;
        }
    }
    return nullptr;
}

const char *ref_class_for_signature(const char *s) {
    static std::map<std::string, const char *> *idx = nullptr;
    if (!idx) {
        idx = new std::map<std::string, const char *>();
        for (uint32_t c = 0; c < kDocClassCount; c++) {
            const char *p = kDocBlob + kDocClasses[c].strings;
            while (p && *p) {
                const char *e = strchr(p, '\x1f');
                const size_t n = e ? (size_t)(e - p) : strlen(p);
                if (n) {
                    const std::string k(p, n);
                    if (!idx->count(k)) (*idx)[k] = kDocBlob + kDocClasses[c].name;
                }
                if (!e) break;
                p = e + 1;
            }
        }
        RCL_LOGLN("[names] signature index: %zu strings over %u classes", idx->size(),
                  kDocClassCount);
    }
    std::map<std::string, const char *>::const_iterator it = idx->find(s);
    return it == idx->end() ? nullptr : it->second;
}

const char *doc_class_name(uint32_t vt) {
    for (uint32_t i = 0; i < kDocClassCount; i++)
        if (kDocClasses[i].vt == vt) return kDocBlob + kDocClasses[i].name;
    return "-";
}

void class_label(uint32_t vt, char *dst, size_t cap) {
    const char *n = doc_class_name(vt);
    if (n && *n && strcmp(n, "-") != 0) {
        snprintf(dst, cap, "%s", n);
        return;
    }
    snprintf(dst, cap, "vt_%06x", vt);
}

std::string hex_label(uint32_t rva) {
    char b[24];
    snprintf(b, sizeof b, "vt_%06x", rva);
    return std::string(b);
}

const char *name_of_table(uint32_t start);
const char *family_of_table(uint32_t start);
const char *category_of_name(const char *name);

const char *doc_category_of_name(const char *name) {
    if (!name || !*name) return nullptr;
    for (uint32_t i = 0; i < kDocClassCount; i++)
        if (strcmp(kDocBlob + kDocClasses[i].name, name) == 0) return kDocBlob + kDocClasses[i].cat;
    return nullptr;
}

std::string word_join(const char *name) {
    std::string out;
    char prev = 0;
    for (const char *p = name; *p; p++) {
        const char c = *p;
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) {
            if (!out.empty() && out[out.size() - 1] != ' ') out.push_back(' ');
            prev = 0;
            continue;
        }
        if (c >= 'A' && c <= 'Z') {
            const bool prev_lower = (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9');
            const bool prev_upper = prev >= 'A' && prev <= 'Z';
            const bool next_lower = p[1] >= 'a' && p[1] <= 'z';
            if (!out.empty() && out[out.size() - 1] != ' ' && (prev_lower || (prev_upper && next_lower)))
                out.push_back(' ');
            out.push_back((char)(c - 'A' + 'a'));
        } else {
            out.push_back(c);
        }
        prev = c;
    }
    while (!out.empty() && out[out.size() - 1] == ' ') out.pop_back();
    return out;
}

const char *category_of_name(const char *name) {
    if (!name || !*name) return "Other";
    const char *exact = doc_category_of_name(name);
    if (exact && *exact) return exact;
    const std::string j = word_join(name);
    if (j.find(':') != std::string::npos) {
        const size_t cut = j.find(':');
        return category_of_name(j.substr(0, cut).c_str());
    }
    static const struct {
        const char *w;
        const char *c;
    } kSuf[] = {
        {"popup", "UI_Popups"},       {"dialogue", "UI_Popups"},   {"dialog", "UI_Popups"},
        {"toast", "UI_Popups"},       {"modal", "UI_Popups"},      {"overlay", "UI_Popups"},
        {"data", "Logic_Data"},       {"config", "Logic_Data"},    {"entry", "Logic_Data"},
        {"info", "Logic_Data"},       {"def", "Logic_Data"},       {"table", "Logic_Data"},
        {"command", "Logic_Commands"},{"server", "Logic_Server"},  {"client", "Logic_Client"},
        {"renderer", "Rendering"},    {"message", "Network_Messages"},
        {"msg", "Network_Messages"},  {"component", "UI_Components"},
        {"item", "UI_Components"},    {"field", "UI_Components"},  {"button", "UI_Components"},
        {"icon", "UI_Components"},    {"tab", "UI_Components"},    {"screen", "UI_Screens"},
        {"page", "UI_Screens"},       {"hud", "UI_Screens"},       {"scene", "UI_Screens"},
        {"manager", "Logic_Core"},    {"system", "Logic_Core"},    {"core", "Logic_Core"},
        {"handler", "Logic_Core"},    {"controller", "Logic_Core"},{"service", "Logic_Core"},
        {"module", "Logic_Core"},     {"registry", "Logic_Core"},  {"state", "Logic_Core"},
        {"audio", "Audio"},           {"sound", "Audio"},          {"sdk", "SDK_Integrations"},
        {"engine", "Engine_Utility"}, {"util", "Engine_Utility"},  {"helper", "Engine_Utility"},
        {"math", "Engine_Utility"},   {"json", "Engine_Utility"},  {"parser", "Engine_Utility"},
        {"pool", "Engine_Utility"},   {"cache", "Engine_Utility"}, {"random", "Engine_Utility"},
    };
    if (!j.empty()) {
        const size_t sp = j.rfind(' ');
        const std::string last = (sp == std::string::npos) ? j : j.substr(sp + 1);
        for (size_t i = 0; i < sizeof kSuf / sizeof kSuf[0]; i++)
            if (last == kSuf[i].w) return kSuf[i].c;
    }
    static const struct {
        const char *c;
        const char *w;
    } kWords[] = {
        {"ThirdParty", " fmod absl boost openssl protobuf zlib lua curl "},
        {"Audio", " audio sound music voice sfx bgm "},
        {"SDK_Integrations",
         " sdk firebase facebook adjust appsflyer gamecenter storekit blinder crashlytics analytics "},
        {"Rendering", " render renderer texture shader sprite camera material particle mesh atlas "
                      "tween vfx "},
        {"Network_Messages", " network message packet protocol socket http rpc "},
        {"Logic_Commands", " command commands "},
        {"Logic_Server", " server "},
        {"Logic_Client", " client "},
        {"Logic_Data", " data config entry def info "},
        {"UI_Popups", " popup dialog modal toast overlay banner alert "},
        {"UI_Screens", " screen page hud scene window loading "},
        {"UI_Components", " button item widget component cell icon tab label slider toggle input "
                          "menu slot badge checkbox switch progress field "},
        {"Logic_Core", " core manager system state controller service registry handler module logic "
                       "process scheduler dispatcher router session "},
        {"Game", " battle player hero match quest reward shop chest level mission event season "
                 "trophy profile friend chat clan brawler arena gamemode character unit skill buff "
                 "team club alliance card "},
        {"Engine_Utility", " engine util helper math string file random json parser cache array hash "
                           "alloc log time date sort buffer stream thread task debug tool "},
    };
    const std::string padded = " " + j + " ";
    for (size_t i = 0; i < sizeof kWords / sizeof kWords[0]; i++) {
        const std::string needle(kWords[i].w);
        for (size_t p = 0; p + 1 < needle.size();) {
            const size_t q = needle.find(' ', p + 1);
            if (q == std::string::npos) break;
            if (padded.find(needle.substr(p, q - p)) != std::string::npos) return kWords[i].c;
            p = q;
        }
    }
    return "Other";
}

struct GlobalHit {
    uint32_t cell;
    uint32_t vt;
    uint64_t object;
};

void scan_globals(const Image &img, const Layout &L, const std::vector<ClassTable> &tables,
                  std::vector<GlobalHit> &out) {
    std::vector<uint32_t> tsorted;
    tsorted.reserve(tables.size());
    for (size_t i = 0; i < tables.size(); i++) tsorted.push_back(tables[i].start);
    std::sort(tsorted.begin(), tsorted.end());
    for (int i = 0; i < L.data_n; i++) {
        for (uint64_t va = L.data[i].start; va + 8 <= L.data[i].end; va += 8) {
            uint64_t obj = 0;
            if (!at(img, va, &obj, 8)) break;
            uint64_t v = 0;
            if (!safe_read8(obj, &v)) {
                uint64_t alt = obj & 0xFFFFFFFFFULL;
                if (!alt || !safe_read8(alt, &v)) continue;
                obj = alt;
            }
            if ((v & 0xFFFFFFFFFULL) < img.base) continue;
            uint32_t vt = (uint32_t)((v & 0xFFFFFFFFFULL) - img.base);
            if (!std::binary_search(tsorted.begin(), tsorted.end(), vt)) continue;
            out.push_back({(uint32_t)(va - img.base), vt, obj});
        }
    }
}

void write_globals(const std::vector<GlobalHit> &hits, const Image &img, const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_globals.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# globals holding objects of a known class (singletons, managers, VTABLE holders)\n\n");
    fprintf(f, "| cell rva | object ptr | where | class table | class | name guess |\n");
    fprintf(f, "|----------|-----------|-------|-------------|-------|------------|\n");
    for (const GlobalHit &h : hits) {
        char cl[128];
        class_label(h.vt, cl, sizeof cl);
        const char *g = "-";
        if (strstr(cl, "BattleScreen")) g = "StageInstanceGlobalPtr-like";
        else if (strstr(cl, "MessageManager")) g = "MessageManager_instance";
        else if (strstr(cl, "AllianceManager")) g = "AllianceManager_instance";
        else if (strstr(cl, "LogicDataTables")) g = "LogicDataTables_tableArray";
        else if (strstr(cl, "FramerateManager")) g = "FramerateManager_targetFps";
        else if (strstr(cl, "Screen")) g = "Screen_*Global";
        const uint64_t span = img.image_vmsize ? img.image_vmsize : img.vmsize;
        const char *where = (h.object >= img.base && h.object - img.base < span) ? "image" : "heap";
        fprintf(f, "| `%#x` | `0x%llx` | %s | `%#x` | %s | %s |\n", h.cell,
                (unsigned long long)h.object, where, h.vt, cl, g);
    }
    fclose(f);

    snprintf(path, sizeof path, "%s/_globals.tsv", root);
    f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "cell_rva\tobject_ptr\twhere\tclass_table\tclass\tname_guess\n");
    for (const GlobalHit &h : hits) {
        char cl[128];
        class_label(h.vt, cl, sizeof cl);
        const char *g = "-";
        if (strstr(cl, "BattleScreen")) g = "StageInstanceGlobalPtr-like";
        else if (strstr(cl, "MessageManager")) g = "MessageManager_instance";
        else if (strstr(cl, "AllianceManager")) g = "AllianceManager_instance";
        else if (strstr(cl, "LogicDataTables")) g = "LogicDataTables_tableArray";
        else if (strstr(cl, "FramerateManager")) g = "FramerateManager_targetFps";
        else if (strstr(cl, "Screen")) g = "Screen_*Global";
        const uint64_t span = img.image_vmsize ? img.image_vmsize : img.vmsize;
        const char *where = (h.object >= img.base && h.object - img.base < span) ? "image" : "heap";
        fprintf(f, "%#x\t0x%llx\t%s\t%#x\t%s\t%s\n", h.cell, (unsigned long long)h.object, where,
                h.vt, cl, g);
    }
    fclose(f);
}

void write_anchors_extra(const std::vector<ClassTable> &tables, const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_vtables.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# class tables of this image (vtables): class -> table rva\n\n");
    fprintf(f, "| class | table rva | slots |\n|-------|-----------|-------|\n");
    for (uint32_t c = 0; c < kDocClassCount; c++) {
        uint32_t vt = kDocClasses[c].vt;
        if (!vt) continue;
        uint32_t slots = 0;
        for (const ClassTable &t : tables)
            if (t.start == vt) slots = t.slots;
        fprintf(f, "| %s | `%#x` | %u |\n", kDocBlob + kDocClasses[c].name, vt, slots);
    }
    fclose(f);
}

}  // namespace

namespace {

struct SlotMap {
    std::vector<uint32_t> sorted;
    std::vector<uint32_t> table_of;

    bool has(uint32_t rva) const { return std::binary_search(sorted.begin(), sorted.end(), rva); }

    uint32_t table_for(uint32_t rva) const {
        uint32_t lo = 0, hi = (uint32_t)sorted.size();
        while (lo < hi) {
            uint32_t mid = (lo + hi) / 2;
            if (sorted[mid] == rva) return table_of[mid];
            if (sorted[mid] < rva) lo = mid + 1;
            else hi = mid;
        }
        return 0;
    }
};

void add_slot(SlotMap &m, uint32_t rva, uint32_t table) {
    m.sorted.push_back(rva);
    m.table_of.push_back(table);
}

void finish_slot_map(SlotMap &m) {
    std::vector<std::pair<uint32_t, uint32_t>> v;
    v.reserve(m.sorted.size());
    for (size_t i = 0; i < m.sorted.size(); i++) v.push_back({m.sorted[i], m.table_of[i]});
    std::sort(v.begin(), v.end());
    m.sorted.clear();
    m.table_of.clear();
    for (size_t i = 0; i < v.size(); i++) {
        m.sorted.push_back(v[i].first);
        m.table_of.push_back(v[i].second);
    }
}

struct FnAgg {
    uint32_t strings = 0;
    uint32_t first_string = 0;
    uint32_t table = 0;
    std::vector<uint32_t> str_list;
    std::vector<uint32_t> calls;
    std::vector<uint32_t> fields;
};

uint32_t adrp_imm(uint32_t w) {
    int imm = (int)(((w >> 5) & 0x7FFFFu) << 2 | ((w >> 29) & 3u));
    if (imm & 0x100000) imm -= 0x200000;
    return (uint32_t)(imm << 12);
}

std::set<uint32_t> g_table_ref;
std::set<uint32_t> g_ctor_table;
std::map<uint32_t, uint32_t> g_table_inst;
std::set<uint32_t> g_table_merged;
bool g_live_ran = false;

uint32_t fn_of_any(const std::vector<uint32_t> &starts, const std::vector<uint32_t> &alt,
                    uint32_t rva) {
    uint32_t fn = fn_of(starts, rva, nullptr);
    if (!fn) fn = fn_of(alt, rva, nullptr);
    return fn;
}

void code_pass(const Image &img, const Layout &L, const std::vector<uint32_t> &starts,
               const std::vector<uint32_t> &alt, const std::vector<StrEnt> &strs,
               const SlotMap &slots, const std::vector<uint32_t> &tabs,
               std::map<uint32_t, FnAgg> &fns) {
    for (uint64_t va = L.code_lo; va + 16 <= L.code_hi; va += 4) {
        uint32_t w0 = 0;
        if (!at(img, va, &w0, 4)) break;
        uint32_t rva = (uint32_t)(va - img.base);
        if ((w0 & 0xFC000000u) == 0x94000000u) {
            int32_t bimm = (int32_t)(w0 & 0x03FFFFFFu);
            if (bimm & 0x02000000) bimm -= 0x04000000;
            int64_t bt = (int64_t)rva + (int64_t)bimm * 4;
            if (bt >= 0 && bt < (int64_t)(L.code_hi - img.base)) {
                uint32_t cf = fn_of_any(starts, alt, rva);
                if (cf && slots.has(cf)) {
                    FnAgg &ca = fns[cf];
                    if (ca.calls.size() < 8 &&
                        std::find(ca.calls.begin(), ca.calls.end(), (uint32_t)bt) == ca.calls.end())
                        ca.calls.push_back((uint32_t)bt);
                }
            }
            continue;
        }
        if ((w0 & 0x9F000000u) != 0x90000000u) {
            uint32_t kind = w0 & 0xFFC00000u;
            if ((kind == 0xB9400000u || kind == 0xB9000000u || kind == 0xF9400000u ||
                 kind == 0xF9000000u) &&
                ((w0 >> 5) & 31u) == 31u) {
                bool word = (kind == 0xB9400000u || kind == 0xB9000000u);
                uint32_t off = ((w0 >> 10) & 0xFFFu) << (word ? 2 : 3);
                if (off >= 8 && off < 0x1000) {
                    uint32_t fn = fn_of_any(starts, alt, rva);
                    if (fn && slots.has(fn)) {
                        FnAgg &a = fns[fn];
                        if (a.fields.size() < 48 &&
                            std::find(a.fields.begin(), a.fields.end(), off) == a.fields.end())
                            a.fields.push_back(off);
                    }
                }
            }
            continue;
        }
        uint32_t rd = w0 & 31u;
        uint64_t page = (uint64_t)(rva & ~0xFFFu) + adrp_imm(w0);
        for (int k = 1; k <= 3; k++) {
            uint32_t wk = 0;
            if (!at(img, va + (uint64_t)k * 4, &wk, 4)) break;
            bool isadd = (wk & 0x7F800000u) == 0x11000000u && ((wk >> 29) & 3u) == 0 &&
                         ((wk >> 5) & 31u) == rd;
            bool isldr = (wk & 0xFFC00000u) == 0xF9400000u && ((wk >> 5) & 31u) == rd;
            if (!isadd && !isldr) continue;
            uint32_t target = (uint32_t)(page + ((wk >> 10) & 0xFFFu));
            if (std::binary_search(tabs.begin(), tabs.end(), target)) {
                g_table_ref.insert(target);
                if (isadd) {
                    for (int q = 1; q <= 3 && k + q <= 3; q++) {
                        uint32_t ws = 0;
                        if (!at(img, va + (uint64_t)(k + q) * 4, &ws, 4)) break;
                        if ((ws & 0xFFC00000u) != 0xF9000000u) continue;
                        if (((ws >> 10) & 0xFFFu) == 0) g_ctor_table.insert(target);
                        break;
                    }
                }
            }
            if (!find_str(strs, target)) continue;
            const uint32_t fn = fn_of_any(starts, alt, rva);
            if (!fn) break;
            FnAgg &a = fns[fn];
            if (!a.first_string) a.first_string = target;
            a.strings++;
            if (a.str_list.size() < kFnStrMax &&
                std::find(a.str_list.begin(), a.str_list.end(), target) == a.str_list.end())
                a.str_list.push_back(target);
            break;
        }
    }
    for (auto &kv : fns) kv.second.table = slots.table_for(kv.first);
}

void write_strings(const Image &img, const std::vector<StrEnt> &strs,
                   const std::map<uint32_t, FnAgg> &fns, const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_strings.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# string anchors: which function references which string (their scanner's data_ref)\n\n"
               "| function rva | class table | class | string | reference class with that string |\n"
               "|--------------|-------------|-------|--------|----------------------------------|\n");
    char buf[512];
    int rows = 0;
    for (const auto &kv : fns) {
        if (!kv.second.strings || !kv.second.first_string) continue;
        const StrEnt *e = find_str(strs, kv.second.first_string);
        if (!e || !read_str(img, *e, buf, sizeof buf)) continue;
        char cl[128];
        const char *n = doc_class_name(kv.second.table);
        snprintf(cl, sizeof cl, "%s", (n && strcmp(n, "-") != 0) ? n : "-");
        const char *owner = ref_class_for_string(buf);
        fprintf(f, "| `%#x` | `%#x` | %s | `%.80s` | %s |\n", kv.first, kv.second.table, cl, buf,
                owner ? owner : "-");
        if (++rows > 6000) break;
    }
    fclose(f);
}

void write_fields(const std::map<uint32_t, FnAgg> &fns, const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_fields.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# candidate field offsets per class (ldr/str [x,#imm] inside the class's functions)\n");
    std::map<std::string, std::map<uint32_t, uint32_t>> per;
    for (const auto &kv : fns) {
        if (!kv.second.table) continue;
        const char *n = doc_class_name(kv.second.table);
        std::string lb = (n && strcmp(n, "-") != 0) ? n : "unnamed";
        for (size_t i = 0; i < kv.second.fields.size(); i++) per[lb][kv.second.fields[i]]++;
    }
    for (const auto &c : per) {
        fprintf(f, "\n## %s\n\n| offset | hits |\n|--------|------|\n", c.first.c_str());
        std::vector<std::pair<uint32_t, uint32_t>> v(c.second.begin(), c.second.end());
        std::sort(v.begin(), v.end(),
                  [](const std::pair<uint32_t, uint32_t> &a, const std::pair<uint32_t, uint32_t> &b) {
                      return a.second > b.second;
                  });
        for (size_t i = 0; i < v.size(); i++) fprintf(f, "| `%#x` | %u |\n", v[i].first, v[i].second);
    }
    fclose(f);
}

void write_all_offsets(const std::vector<ClassTable> &tables, const SlotMap &slots,
                       const std::map<uint32_t, FnAgg> &fns, const std::vector<GlobalHit> &gh,
                       const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_all_offsets.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# every offset this build can find, in one file\n\n");
    uint32_t str_only = 0;
    for (std::map<uint32_t, FnAgg>::const_iterator it = fns.begin(); it != fns.end(); ++it)
        if (it->second.first_string) str_only++;
    fprintf(f, "documented classes %u | class tables %zu | table slots %zu | globals holding known "
               "objects %zu | functions with a string anchor %u (of %zu scanned)\n\n",
            kDocClassCount, tables.size(), slots.sorted.size(), gh.size(), str_only, fns.size());
    fprintf(f, "| class | folder | table rva | slots | slots named by string | field candidates |\n");
    fprintf(f, "|-------|--------|-----------|-------|----------------------|------------------|\n");
    for (size_t i = 0; i < tables.size(); i++) {
        const ClassTable &t = tables[i];
        const char *n = name_of_table(t.start);
        const char *nf = (!n || !*n) ? family_of_table(t.start) : nullptr;
        std::string lb = n ? std::string(n) : hex_label(t.start);
        uint32_t named = 0, flds = 0;
        for (const auto &kv : fns)
            if (kv.second.table == t.start) {
                if (kv.second.strings) named++;
                flds += (uint32_t)kv.second.fields.size();
            }
        fprintf(f, "| %s | %s | `%#x` | %u | %u | %u |\n", lb.c_str(),
                (n || nf) ? category_of_name(n ? lb.c_str() : nf) : "-", t.start, t.slots, named,
                flds);
    }
    fclose(f);
}

std::map<uint32_t, std::string> g_table_class;

struct DeepSummary {
    uint32_t starts = 0;
    uint32_t strings = 0;
    uint32_t anchored = 0;
    uint32_t globals = 0;
    uint32_t named = 0;
    uint32_t tables = 0;
    uint32_t slots = 0;
    uint32_t method_named = 0;
    uint32_t seeded = 0;
    uint32_t families = 0;
    uint32_t registry = 0;
    uint32_t sandwiched = 0;
    uint32_t tu_clustered = 0;
};

DeepSummary g_deep;
bool g_deep_ready = false;
std::set<uint32_t> g_tree_written;

std::map<uint32_t, std::string> g_table_family;
std::map<uint32_t, const char *> g_table_src;


typedef std::map<uint32_t, std::pair<std::string, const char *>> CandMap;

void commit_names(const CandMap &cand) {
    std::map<std::string, uint32_t> used;
    for (CandMap::const_iterator it = cand.begin(); it != cand.end(); ++it) used[it->second.first]++;
    for (std::map<uint32_t, std::string>::const_iterator it = g_table_class.begin();
         it != g_table_class.end(); ++it)
        used[it->second]++;
    for (CandMap::const_iterator it = cand.begin(); it != cand.end(); ++it) {
        if (g_table_class.count(it->first)) continue;
        if (used[it->second.first] > 1) {
            g_table_family[it->first] = it->second.first;
            continue;
        }
        g_table_class[it->first] = it->second.first;
        g_table_src[it->first] = it->second.second;
    }
}

const char *name_of_table(uint32_t start) {
    std::map<uint32_t, std::string>::iterator it = g_table_class.find(start);
    if (it != g_table_class.end()) return it->second.c_str();
    const char *n = doc_class_name(start);
    return (n && strcmp(n, "-") != 0) ? n : nullptr;
}

const char *family_of_table(uint32_t start) {
    std::map<uint32_t, std::string>::const_iterator it = g_table_family.find(start);
    if (it != g_table_family.end() && !it->second.empty()) return it->second.c_str();
    return nullptr;
}

bool class_from_text(const char *s, char *out, size_t cap) {
    for (const char *p = s; *p; p++) {
        if (*p < 'A' || *p > 'Z') continue;
        if (p != s) {
            char b = p[-1];
            if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
                b == '_' || b == ':')
                continue;
        }
        const char *q = p;
        while ((*q >= 'A' && *q <= 'Z') || (*q >= 'a' && *q <= 'z') || (*q >= '0' && *q <= '9') ||
               *q == '_')
            q++;
        if (q - p < 3 || q[0] != ':' || q[1] != ':') continue;
        const char *r = q + 2;
        if (!((*r >= 'A' && *r <= 'Z') || (*r >= 'a' && *r <= 'z') || *r == '~')) continue;
        size_t n = (size_t)(q - p);
        if (n >= cap) n = cap - 1;
        memcpy(out, p, n);
        out[n] = 0;
        return true;
    }
    return false;
}

void slots_of(const Image &img, const ClassTable &t, std::vector<uint32_t> &out, uint32_t cap) {
    out.clear();
    for (uint32_t s = 0; s < t.slots && out.size() < cap; s++) {
        uint64_t raw = 0;
        if (!at(img, img.base + t.start + (uint64_t)s * 8, &raw, sizeof(raw))) break;
        out.push_back((uint32_t)((raw & 0xFFFFFFFFFULL) - img.base));
    }
    std::sort(out.begin(), out.end());
}

void name_tables_from_strings(const Image &img, const std::vector<StrEnt> &strs,
                              const std::vector<ClassTable> &tables,
                              const std::map<uint32_t, FnAgg> &fns) {
    char buf[512];
    char cbuf[128];
    CandMap cand;
    for (size_t i = 0; i < tables.size(); i++) {
        const ClassTable &t = tables[i];
        std::map<std::string, uint32_t> votes;
        std::map<std::string, uint32_t> votes1;
        std::map<std::string, uint32_t> own;
        for (uint32_t s = 0; s < t.slots; s++) {
            uint64_t raw = 0;
            if (!at(img, img.base + t.start + (uint64_t)s * 8, &raw, sizeof(raw))) break;
            uint32_t sr = (uint32_t)((raw & 0xFFFFFFFFFULL) - img.base);
            std::map<uint32_t, FnAgg>::const_iterator it = fns.find(sr);
            if (it == fns.end() || (it->second.str_list.empty() && it->second.calls.empty()))
                continue;
            for (size_t k = 0; k < it->second.str_list.size(); k++) {
                const StrEnt *e = find_str(strs, it->second.str_list[k]);
                if (!e || !read_str(img, *e, buf, sizeof buf)) continue;
                const bool cs = class_specific_string(buf);
                const char *owner = ref_class_for_signature(buf);
                if (owner) votes[owner] += cs ? 2 : 1;
                if (cs && class_from_text(buf, cbuf, sizeof cbuf)) own[cbuf] += 1;
            }
            for (size_t c = 0; c < it->second.calls.size(); c++) {
                std::map<uint32_t, FnAgg>::const_iterator ci = fns.find(it->second.calls[c]);
                if (ci == fns.end()) continue;
                for (size_t k = 0; k < ci->second.str_list.size(); k++) {
                    const StrEnt *e2 = find_str(strs, ci->second.str_list[k]);
                    if (!e2 || !read_str(img, *e2, buf, sizeof buf)) continue;
                    const char *o2 = ref_class_for_signature(buf);
                    if (o2) votes1[o2] += 1;
                }
            }
        }
        uint32_t best = 0;
        std::string bestn;
        for (std::map<std::string, uint32_t>::iterator it = votes.begin(); it != votes.end(); ++it)
            if (it->second > best) {
                best = it->second;
                bestn = it->first;
            }
        const char *src = "string anchor";
        if (!best) {
            uint32_t best1 = 0;
            std::string bestn1;
            for (std::map<std::string, uint32_t>::iterator it = votes1.begin(); it != votes1.end();
                 ++it)
                if (it->second > best1) {
                    best1 = it->second;
                    bestn1 = it->first;
                }
            if (best1 >= 2) {
                best = best1;
                bestn = bestn1;
                src = "called from";
            }
        }
        if (!best) {
            for (std::map<std::string, uint32_t>::iterator it = own.begin(); it != own.end(); ++it)
                if (it->second > best) {
                    best = it->second;
                    bestn = it->first;
                }
            src = "class::method";
        }
        if (best) cand[t.start] = std::make_pair(bestn, src);
    }
    commit_names(cand);
}

void name_from_method_index(const Image &img, const std::vector<ClassTable> &tables,
                            uint32_t *out_named, const char *root) {
    std::map<uint32_t, const char *> m2c;
    for (uint32_t c = 0; c < kDocClassCount; c++) {
        const DocClass &d = kDocClasses[c];
        for (uint16_t k = 0; k < d.count; k++) m2c[kDocMethods[d.first + k].rva] = kDocBlob + d.name;
    }
    std::map<uint32_t, uint32_t> occ;
    std::vector<uint32_t> sv;
    for (size_t i = 0; i < tables.size(); i++) {
        slots_of(img, tables[i], sv, 256);
        for (size_t k = 0; k < sv.size(); k++)
            if (m2c.count(sv[k])) occ[sv[k]]++;
    }
    uint32_t named = 0;
    CandMap cand;
    char path[1024];
    snprintf(path, sizeof path, "%s/_method_index.md", root);
    FILE *f = fopen(path, "w");
    if (f)
        fprintf(f, "# tables named by a documented method address that sits in exactly one table\n\n"
                   "| table rva | slots | hits | class |\n|-----------|-------|------|-------|\n");
    for (size_t i = 0; i < tables.size(); i++) {
        const ClassTable &t = tables[i];
        slots_of(img, t, sv, 256);
        std::map<std::string, uint32_t> votes;
        for (size_t k = 0; k < sv.size(); k++) {
            std::map<uint32_t, const char *>::iterator mi = m2c.find(sv[k]);
            if (mi == m2c.end() || occ[sv[k]] != 1) continue;
            votes[mi->second]++;
        }
        if (votes.empty()) continue;
        std::string best;
        uint32_t top = 0;
        for (std::map<std::string, uint32_t>::iterator it = votes.begin(); it != votes.end(); ++it)
            if (it->second > top) {
                top = it->second;
                best = it->first;
            }
        if (!top) continue;
        cand[t.start] = std::make_pair(best, "method-index");
        named++;
        if (f) fprintf(f, "| `%#x` | %u | %u | %s |\n", t.start, t.slots, top, best.c_str());
    }
    if (f) fclose(f);
    commit_names(cand);
    if (out_named) *out_named = named;
}

struct Sandw {
    const char *lo;
    const char *hi;
    std::vector<uint32_t> vts;
};

void sandwiches(const std::vector<ClassTable> &tables, std::vector<Sandw> &out,
                uint32_t *out_blocks, uint32_t *out_ordered) {
    std::vector<const ClassTable *> by;
    by.reserve(tables.size());
    for (size_t i = 0; i < tables.size(); i++) by.push_back(&tables[i]);
    std::sort(by.begin(), by.end(),
              [](const ClassTable *a, const ClassTable *b) { return a->start < b->start; });
    size_t i = 0;
    uint32_t blocks = 0, ordered = 0;
    while (i < by.size()) {
        size_t j = i + 1;
        while (j < by.size() && by[j]->start - by[j - 1]->start <= kBlockGap) j++;
        blocks++;
        uint32_t seeds = 0, inc = 0;
        const char *prev = nullptr;
        for (size_t k = i; k < j; k++) {
            const char *n = name_of_table(by[k]->start);
            if (!n) continue;
            seeds++;
            if (prev && strcmp(prev, n) < 0) inc++;
            prev = n;
        }
        if (seeds >= kBlockMinSeeds && inc * 4 >= (seeds - 1) * 3) {
            ordered++;
            const char *lo = nullptr;
            Sandw cur;
            cur.lo = nullptr;
            cur.hi = nullptr;
            for (size_t k = i; k < j; k++) {
                const char *n = name_of_table(by[k]->start);
                if (n) {
                    if (cur.lo && !cur.vts.empty()) {
                        cur.hi = n;
                        out.push_back(cur);
                    }
                    lo = n;
                    cur.lo = lo;
                    cur.hi = nullptr;
                    cur.vts.clear();
                    continue;
                }
                if (cur.lo) cur.vts.push_back(by[k]->start);
            }
        }
        i = j;
    }
    if (out_blocks) *out_blocks = blocks;
    if (out_ordered) *out_ordered = ordered;
}

void write_order_hint(const std::vector<ClassTable> &tables, const char *root,
                      const std::vector<Sandw> &sw) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_order_hint.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# unnamed tables between two named ones inside an alphabetically ordered block\n\n"
               "the linker sorts class tables by name, so the name of each row below is "
               "alphabetically between `prev` and `next`\n\n");
    fprintf(f, "| prev | next | table rva | slots |\n|------|------|-----------|-------|\n");
    size_t total = 0;
    for (size_t i = 0; i < sw.size(); i++)
        for (size_t k = 0; k < sw[i].vts.size(); k++) {
            uint32_t slots = 0;
            for (size_t t = 0; t < tables.size(); t++)
                if (tables[t].start == sw[i].vts[k]) slots = tables[t].slots;
            fprintf(f, "| %s | %s | `%#x` | %u |\n", sw[i].lo, sw[i].hi, sw[i].vts[k], slots);
            total++;
        }
    fprintf(f, "\n%zu tables carry an order constraint\n", total);
    fclose(f);
}

void cluster_families(const Image &img, const std::vector<ClassTable> &tables, const char *root,
                      uint32_t *out_named) {
    std::map<uint32_t, std::vector<uint32_t>> sv;
    std::vector<uint32_t> tmp;
    std::vector<uint32_t> namedv;
    for (size_t i = 0; i < tables.size(); i++) {
        slots_of(img, tables[i], tmp, 256);
        sv[tables[i].start] = tmp;
        if (name_of_table(tables[i].start)) namedv.push_back(tables[i].start);
    }
    char path[1024];
    snprintf(path, sizeof path, "%s/_clusters.md", root);
    FILE *f = fopen(path, "w");
    if (f)
        fprintf(f, "# tables sharing half of their slots with a named table (same hierarchy)\n\n"
                   "| table rva | slots | shared | named table | family |\n"
                   "|-----------|-------|--------|-------------|--------|\n");
    uint32_t hits = 0;
    std::vector<uint32_t> inter;
    for (std::map<uint32_t, std::vector<uint32_t>>::iterator it = sv.begin(); it != sv.end(); ++it) {
        if (name_of_table(it->first) || it->second.size() < kClusterSharedMin) continue;
        uint32_t best = 0;
        const char *bestn = nullptr;
        for (size_t k = 0; k < namedv.size(); k++) {
            if (sv[namedv[k]].size() < kClusterSharedMin) continue;
            inter.clear();
            std::set_intersection(it->second.begin(), it->second.end(), sv[namedv[k]].begin(),
                                  sv[namedv[k]].end(), std::back_inserter(inter));
            if (inter.size() > best) {
                best = (uint32_t)inter.size();
                bestn = name_of_table(namedv[k]);
            }
        }
        if (best >= kClusterSharedMin && best * 2 >= (uint32_t)it->second.size()) {
            g_table_family[it->first] = bestn;
            hits++;
            if (f)
                fprintf(f, "| `%#x` | %zu | %u | %s | ~%s |\n", it->first, it->second.size(), best,
                        bestn, bestn);
        }
    }
    if (f) fclose(f);
    if (out_named) *out_named = hits;
}

struct RegPair {
    uint32_t cell;
    uint32_t vt;
    char text[96];
};

void scan_registry(const Image &img, const Layout &L, const std::vector<ClassTable> &tables,
                   std::vector<RegPair> &out) {
    std::vector<uint32_t> ts;
    for (size_t i = 0; i < tables.size(); i++) ts.push_back(tables[i].start);
    std::sort(ts.begin(), ts.end());
    for (int i = 0; i < L.data_n; i++) {
        uint64_t va = L.data[i].start;
        while (va + 8 <= L.data[i].end) {
            uint64_t raw = 0;
            if (!at(img, va, &raw, sizeof(raw))) break;
            uint64_t p = raw & 0xFFFFFFFFFULL;
            uint32_t rva = (uint32_t)(p - img.base);
            if (p < img.base || !std::binary_search(ts.begin(), ts.end(), rva)) {
                va += 8;
                continue;
            }
            for (int d = -8; d <= 8; d++) {
                uint64_t cell = va + (uint64_t)(d * 8);
                if (cell < L.data[i].start || cell + 8 > L.data[i].end) continue;
                uint64_t q = 0;
                if (!at(img, cell, &q, sizeof(q))) continue;
                uint64_t sp = q & 0xFFFFFFFFFULL;
                if (sp < L.code_lo || sp >= L.code_hi) continue;
                uint32_t len = text_len(img, sp, L.code_hi, 95);
                if (len < 3) continue;
                RegPair rp;
                rp.cell = (uint32_t)(va - img.base);
                rp.vt = rva;
                if (!at(img, sp, rp.text, len)) continue;
                rp.text[len] = 0;
                out.push_back(rp);
                break;
            }
            va += 8;
        }
    }
}

void write_registry(const std::vector<RegPair> &pairs, const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_registry.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# cells that hold a class table next to a string (engine registries)\n\n"
               "| cell rva | class table | class | string |\n|----------|-------------|-------|--------|\n");
    for (size_t i = 0; i < pairs.size(); i++) {
        const char *n = name_of_table(pairs[i].vt);
        fprintf(f, "| `%#x` | `%#x` | %s | `%.70s` |\n", pairs[i].cell, pairs[i].vt,
                n ? n : "?", pairs[i].text);
    }
    fclose(f);
}

extern "C" uint32_t _dyld_image_count(void);
extern "C" const void *_dyld_get_image_header(uint32_t index);
extern "C" intptr_t _dyld_get_image_vmaddr_slide(uint32_t index);

struct SectionRef {
    char seg[17];
    char sect[17];
    uint64_t addr;
    uint64_t size;
};

int image_sections(const Image &img, uint64_t base, SectionRef *out, int cap) {
    Mh mh;
    if (!at(img, base, &mh, sizeof(mh)) || mh.magic != 0xFEEDFACFu) return 0;
    int n = 0;
    uint64_t p = base + sizeof(Mh);
    for (uint32_t c = 0; c < mh.ncmds; c++) {
        Lc lc;
        if (!at(img, p, &lc, sizeof(lc))) break;
        if (lc.cmdsize < sizeof(Lc) || lc.cmdsize > 0x10000) break;
        if (lc.cmd == kLcSegment64) {
            SegCmd sg;
            if (at(img, p, &sg, sizeof(sg))) {
                struct Sec {
                    char sectname[16];
                    char segname[16];
                    uint64_t addr;
                    uint64_t size;
                    uint32_t off;
                    uint32_t align;
                    uint32_t reloff;
                    uint32_t nreloc;
                    uint32_t flags;
                    uint32_t r1;
                    uint32_t r2;
                    uint32_t r3;
                };
                uint64_t sp = p + sizeof(SegCmd);
                for (uint32_t s = 0; s < sg.nsects && n < cap; s++) {
                    Sec sc;
                    if (!at(img, sp, &sc, sizeof(sc))) break;
                    memcpy(out[n].sect, sc.sectname, 16);
                    out[n].sect[16] = 0;
                    memcpy(out[n].seg, sc.segname, 16);
                    out[n].seg[16] = 0;
                    out[n].addr = sc.addr;
                    out[n].size = sc.size;
                    n++;
                    sp += sizeof(sc);
                }
            }
        }
        p += lc.cmdsize;
    }
    return n;
}

void import_foreign_names(const Image &img, const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_objc.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# ObjC and Swift names in every loaded image\n\n");
    uint32_t images = _dyld_image_count();
    uint32_t total = 0;
    uint32_t ref = 0;
    char buf[256];
    for (uint32_t i = 0; i < images; i++) {
        const void *h = _dyld_get_image_header(i);
        if (!h) continue;
        SectionRef sr[128];
        int n = image_sections(img, (uint64_t)(uintptr_t)h, sr, 128);
        for (int k = 0; k < n; k++) {
            if (strncmp(sr[k].sect, "__objc_classname", 16) != 0) continue;
            uint64_t p = sr[k].addr;
            uint64_t end = sr[k].addr + sr[k].size;
            while (p < end) {
                uint32_t len = text_len(img, p, end, 255);
                if (len >= 3 && at(img, p, buf, len)) {
                    buf[len] = 0;
                    total++;
                    bool doc = false;
                    for (uint32_t c = 0; c < kDocClassCount; c++)
                        if (strcmp(kDocBlob + kDocClasses[c].name, buf) == 0) {
                            doc = true;
                            break;
                        }
                    if (doc) ref++;
                    fprintf(f, "- `%s`%s\n", buf, doc ? " (in the reference)" : "");
                }
                p += len + 1;
            }
        }
    }
    fprintf(f, "\n%u ObjC/Swift class names, %u of them in the class reference\n", total, ref);
    fclose(f);
    RCL_LOGLN("[deep] foreign names: images=%u objc=%u in_reference=%u", images, total, ref);
}

void external_align(const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_external.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    snprintf(path, sizeof path, "%s/names.txt", root);
    FILE *in = fopen(path, "r");
    fprintf(f, "# external class list aligned to the memory order of the tables\n\n");
    if (!in) {
        fprintf(f, "no `names.txt` in `%s` - one class name per line enables this stage\n", root);
        fclose(f);
        return;
    }
    char line[256];
    uint32_t n = 0;
    while (fgets(line, sizeof(line), in)) {
        size_t l = strlen(line);
        while (l && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = 0;
        if (l) n++;
    }
    fclose(in);
    fprintf(f, "%u names read\n", n);
    fclose(f);
}

void branch_starts(const Image &img, const Layout &L, std::vector<uint32_t> &out) {
    const int64_t hi = (int64_t)(L.code_hi - img.base);
    for (uint64_t va = L.code_lo; va + 4 <= L.code_hi; va += 4) {
        uint32_t w = 0;
        if (!at(img, va, &w, 4)) break;
        if ((w & 0xFC000000u) != 0x94000000u) continue;
        int32_t imm = (int32_t)(w & 0x03FFFFFFu);
        if (imm & 0x02000000) imm -= 0x04000000;
        int64_t t = (int64_t)(va - img.base) + (int64_t)imm * 4;
        if (t < 0 || t >= hi) continue;
        out.push_back((uint32_t)t);
    }
}

bool lc_function_starts(const Image &img, const Layout &L, std::vector<uint32_t> &out) {
    Mh mh;
    if (!at(img, img.base, &mh, sizeof(mh)) || mh.magic != 0xFEEDFACFu) return false;
    uint64_t le_off = 0, le_va = 0;
    uint32_t dataoff = 0, datasize = 0;
    uint64_t p = img.base + sizeof(Mh);
    for (uint32_t c = 0; c < mh.ncmds; c++) {
        Lc lc;
        if (!at(img, p, &lc, sizeof(lc))) return false;
        if (lc.cmdsize < sizeof(Lc) || lc.cmdsize > 0x10000) return false;
        if (lc.cmd == kLcSegment64) {
            SegCmd sg;
            if (at(img, p, &sg, sizeof(sg)) && strncmp(sg.segname, "__LINKEDIT", 11) == 0) {
                le_off = sg.fileoff;
                le_va = sg.vmaddr;
            }
        } else if (lc.cmd == kLcFunctionStarts) {
            struct FsCmd {
                uint32_t cmd;
                uint32_t cmdsize;
                uint32_t dataoff;
                uint32_t datasize;
            } fs;
            if (at(img, p, &fs, sizeof(fs))) {
                dataoff = fs.dataoff;
                datasize = fs.datasize;
            }
        }
        p += lc.cmdsize;
    }
    if (!datasize || dataoff < le_off) return false;
    uint64_t va = le_va + (dataoff - le_off) + L.slide;
    uint64_t end = va + datasize;
    uint32_t rva = 0;
    while (va < end) {
        uint8_t b = 0;
        uint32_t shift = 0, delta = 0;
        bool ok = false;
        for (;;) {
            if (!at(img, va, &b, 1)) return !out.empty();
            va += 1;
            delta |= (uint32_t)(b & 0x7Fu) << shift;
            shift += 7;
            if (!(b & 0x80u)) {
                ok = true;
                break;
            }
            if (shift > 28) break;
        }
        if (!ok || !delta) break;
        rva += delta;
        out.push_back(rva);
    }
    return !out.empty();
}


void data_refs(const Image &img, const Layout &L, const std::vector<uint32_t> &tabs) {
    for (int i = 0; i < L.data_n; i++) {
        for (uint64_t va = L.data[i].start; va + 8 <= L.data[i].end; va += 8) {
            uint64_t raw = 0;
            if (!at(img, va, &raw, sizeof(raw))) break;
            uint32_t r = (uint32_t)((raw & 0xFFFFFFFFFULL) - img.base);
            if (std::binary_search(tabs.begin(), tabs.end(), r)) g_table_ref.insert(r);
        }
    }
}

void expand_calls(std::map<uint32_t, FnAgg> &fns) {
    std::map<uint32_t, std::vector<uint32_t>> add;
    for (std::map<uint32_t, FnAgg>::iterator it = fns.begin(); it != fns.end(); ++it) {
        for (size_t c = 0; c < it->second.calls.size(); c++) {
            std::map<uint32_t, FnAgg>::const_iterator ci = fns.find(it->second.calls[c]);
            if (ci == fns.end()) continue;
            for (size_t k = 0; k < ci->second.str_list.size(); k++) {
                uint32_t v = ci->second.str_list[k];
                if (std::find(it->second.str_list.begin(), it->second.str_list.end(), v) !=
                    it->second.str_list.end())
                    continue;
                add[it->first].push_back(v);
            }
        }
    }
    for (std::map<uint32_t, std::vector<uint32_t>>::iterator it = add.begin(); it != add.end(); ++it) {
        FnAgg &a = fns[it->first];
        for (size_t k = 0; k < it->second.size() && a.str_list.size() < 24; k++)
            a.str_list.push_back(it->second[k]);
    }
}

bool all_slots_are_starts(const Image &img, const ClassTable &t, const std::vector<uint32_t> &starts,
                          std::vector<uint32_t> &sv) {
    slots_of(img, t, sv, 256);
    for (size_t k = 0; k < sv.size(); k++) {
        bool exact = false;
        fn_of(starts, sv[k], &exact);
        if (!exact) return false;
    }
    return true;
}

uint32_t merge_runs(const Image &img, const std::vector<ClassTable> &tables,
                    const std::vector<uint32_t> &starts, uint32_t *out_cand) {
    std::vector<const ClassTable *> by;
    by.reserve(tables.size());
    for (size_t i = 0; i < tables.size(); i++) by.push_back(&tables[i]);
    std::sort(by.begin(), by.end(),
              [](const ClassTable *a, const ClassTable *b) { return a->start < b->start; });
    uint32_t cand = 0, applied = 0;
    std::vector<uint32_t> sv;
    for (size_t i = 1; i < by.size(); i++) {
        const uint64_t end = by[i - 1]->start + (uint64_t)by[i - 1]->slots * 8;
        if (by[i]->start < end) continue;
        if (by[i]->start - end > 0x20) continue;
        if (by[i - 1]->slots + by[i]->slots > 256) continue;
        cand++;
        if (!all_slots_are_starts(img, *by[i - 1], starts, sv)) continue;
        if (!all_slots_are_starts(img, *by[i], starts, sv)) continue;
        applied++;
        g_table_merged.insert(by[i]->start);
    }
    if (out_cand) *out_cand = cand;
    return applied;
}

uint32_t dup_tables(const Image &img, const std::vector<ClassTable> &tables) {
    std::map<std::string, uint32_t> seen;
    std::vector<uint32_t> sv;
    uint32_t dup = 0;
    for (size_t i = 0; i < tables.size(); i++) {
        if (g_table_merged.count(tables[i].start)) continue;
        slots_of(img, tables[i], sv, 64);
        std::string key((const char *)sv.data(), sv.size() * sizeof(uint32_t));
        if (seen.count(key)) dup++;
        else seen[key] = tables[i].start;
    }
    return dup;
}

void tu_cluster(const Image &img, const std::vector<ClassTable> &tables, uint32_t *out) {
    std::map<uint32_t, std::vector<uint32_t>> sv;
    std::vector<uint32_t> tmp;
    std::vector<uint32_t> seeds;
    for (size_t i = 0; i < tables.size(); i++) {
        slots_of(img, tables[i], tmp, 64);
        sv[tables[i].start] = tmp;
        if (tables[i].start == 0) continue;
    }
    std::map<uint32_t, const char *> known;
    for (std::map<uint32_t, std::string>::iterator it = g_table_family.begin(); it != g_table_family.end(); ++it)
        known[it->first] = it->second.c_str();
    for (std::map<uint32_t, std::string>::iterator it = g_table_class.begin(); it != g_table_class.end(); ++it)
        known[it->first] = it->second.c_str();
    for (std::map<uint32_t, const char *>::iterator it = known.begin(); it != known.end(); ++it)
        seeds.push_back(it->first);
    uint32_t hits = 0;
    for (std::map<uint32_t, std::vector<uint32_t>>::iterator it = sv.begin(); it != sv.end(); ++it) {
        if (known.count(it->first) || it->second.empty()) continue;
        uint32_t best = 0xFFFFFFFFu;
        const char *bestn = nullptr;
        for (size_t k = 0; k < seeds.size(); k++) {
            const std::vector<uint32_t> &o = sv[seeds[k]];
            if (o.empty()) continue;
            size_t a = 0, b = 0;
            uint32_t d = 0xFFFFFFFFu, n = 0;
            while (a < it->second.size() && b < o.size() && n < 3) {
                uint32_t x = it->second[a] > o[b] ? it->second[a] - o[b] : o[b] - it->second[a];
                if (x < d) d = x;
                if (it->second[a] < o[b]) a++;
                else b++;
                n++;
            }
            if (d < best) {
                best = d;
                bestn = known[seeds[k]];
            }
        }
        if (bestn && best < 0x800) {
            g_table_family[it->first] = bestn;
            hits++;
        }
    }
    if (out) *out = hits;
}

#if defined(__APPLE__) || defined(RCL_HOST_TEST)
extern "C" int mach_vm_region(unsigned int task, unsigned long long *address,
                              unsigned long long *size, int flavor, void *info,
                              unsigned int *count, unsigned int *object_name);
struct VmRegion64 {
    unsigned long long protection;
    unsigned long long max_protection;
    unsigned int inheritance;
    unsigned int shared;
    unsigned int reserved;
    unsigned int offset;
    unsigned int behavior;
    unsigned int user_wired_count;
};
void live_census(const Image &img, const std::vector<uint32_t> &tabs) {
    if (tabs.empty()) return;
    unsigned long long addr = 0, size = 0;
    VmRegion64 info;
    unsigned int cnt = 9;
    int guard = 0;
    unsigned int obj = 0;
    uint64_t budget = 4u << 20;
    while (guard < 6000 && budget &&
           mach_vm_region(mach_task_self_, &addr, &size, 9, &info, &cnt, &obj) == 0) {
        if (size >= 0x1000 && size <= 0x4000000ULL && info.protection == 3) {
            for (unsigned long long a = addr; a + 8 <= addr + size && budget; a += 8) {
                uint64_t w = 0;
                unsigned long long got = 0;
                budget--;
                if (mach_vm_read_overwrite(mach_task_self_, a, 8, (unsigned long long)&w, &got) != 0)
                    break;
                uint32_t r = (uint32_t)((w & 0xFFFFFFFFFULL) - img.base);
                if (r < 0x1200000u && std::binary_search(tabs.begin(), tabs.end(), r))
                    g_table_inst[r]++;
            }
        }
        guard++;
        addr += size ? size : 0x1000;
        size = 0;
        cnt = 9;
    }
    g_live_ran = true;
}
#else
void live_census(const Image &, const std::vector<uint32_t> &) {}
#endif

void write_confidence(const std::vector<ClassTable> &tables, const char *root, uint32_t merged,
                      uint32_t cand, uint32_t dup) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_confidence.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# which tables are real classes, in three independent tests\n\n"
               "a table is a class when the image references it, a constructor installs it, "
               "or a live object carries it\n\n");
    fprintf(f, "| table rva | slots | class | referenced | ctor | instances |\n"
               "|-----------|-------|-------|------------|------|-----------|\n");
    uint32_t ref = 0, ctor = 0, live = 0, both = 0;
    for (size_t i = 0; i < tables.size(); i++) {
        const ClassTable &t = tables[i];
        const bool r = g_table_ref.count(t.start) != 0;
        const bool c = g_ctor_table.count(t.start) != 0;
        std::map<uint32_t, uint32_t>::const_iterator ii = g_table_inst.find(t.start);
        const uint32_t n = ii == g_table_inst.end() ? 0 : ii->second;
        if (r) ref++;
        if (c) ctor++;
        if (n) live++;
        if (r && c) both++;
        const char *nm = name_of_table(t.start);
        if (r || c || n)
            fprintf(f, "| `%#x` | %u | %s | %s | %s | %s |%s\n", t.start, t.slots, nm ? nm : "?",
                    r ? "yes" : "-", c ? "yes" : "-",
                    g_live_ran ? (n ? "instances" : "-") : "not measured",
                    g_table_merged.count(t.start) ? " merged" : "");
    }
    fprintf(f, "\n%u tables, referenced %u, ctor installed %u, referenced+ctor %u\n",
            (uint32_t)tables.size(), ref, ctor, both);
    fprintf(f, "live instances %s\n", g_live_ran ? "measured above" : "NOT MEASURED here");
    fprintf(f, "runs merged into the previous table: %u of %u candidates\n", merged, cand);
    fprintf(f, "after merging, tables whose slot vector repeats an earlier table: %u\n", dup);
    fclose(f);
    RCL_LOGLN("[deep] confidence: ref=%u ctor=%u live=%u merged=%u dup=%u", ref, ctor, live, merged,
              dup);
}

void write_table_names(const std::vector<ClassTable> &tables, const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_table_names.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# class table -> class name, resolved from the strings its functions reference\n\n");
    fprintf(f, "| table rva | slots | class | source |\n|-----------|-------|-------|--------|\n");
    uint32_t named = 0;
    uint32_t from_strings = 0;
    for (size_t i = 0; i < tables.size(); i++) {
        const ClassTable &t = tables[i];
        std::map<uint32_t, std::string>::iterator it = g_table_class.find(t.start);
        const char *old = doc_class_name(t.start);
        const bool has_ref = strcmp(old, "-") != 0;
        std::map<uint32_t, const char *>::const_iterator si = g_table_src.find(t.start);
        if (it == g_table_class.end()) {
            fprintf(f, "| `%#x` | %u | %s | reference |\n", t.start, t.slots, has_ref ? old : "?");
            continue;
        }
        named++;
        if (si != g_table_src.end()) from_strings++;
        fprintf(f, "| `%#x` | %u | %s | %s%s%s |\n", t.start, t.slots, it->second.c_str(),
                si == g_table_src.end() ? "reference" : si->second, has_ref ? " + " : "",
                has_ref ? old : "");
    }
    std::map<uint32_t, std::string>::const_iterator fi;
    for (fi = g_table_family.begin(); fi != g_table_family.end(); ++fi)
        fprintf(f, "| `%#x` | - | ~%s | family |\n", fi->first, fi->second.c_str());
    fclose(f);
    RCL_LOGLN("[deep] tables named: %u (from strings %u, from families %zu)", named, from_strings,
              g_table_family.size());
}

void write_unknown_named(const Image &img, const std::vector<StrEnt> &strs,
                         const std::vector<ClassTable> &tables,
                         const std::map<uint32_t, FnAgg> &fns, const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_unknown_named.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# tables the reference does not know, now named by their strings\n\n");
    char buf[512];
    for (size_t i = 0; i < tables.size(); i++) {
        const ClassTable &t = tables[i];
        if (strcmp(doc_class_name(t.start), "-") != 0) continue;
        std::map<uint32_t, std::string>::iterator it = g_table_class.find(t.start);
        if (it == g_table_class.end()) continue;
        fprintf(f, "\n## %s\n\n`table=%#x slots=%u`\n\n| slot rva | string its function uses |\n"
                   "|----------|-------------------------|\n", it->second.c_str(), t.start, t.slots);
        for (uint32_t s = 0; s < t.slots; s++) {
            uint64_t raw = 0;
            if (!at(img, img.base + t.start + (uint64_t)s * 8, &raw, sizeof(raw))) break;
            uint32_t sr = (uint32_t)((raw & 0xFFFFFFFFFULL) - img.base);
            std::map<uint32_t, FnAgg>::const_iterator fi = fns.find(sr);
            const char *txt = "-";
            if (fi != fns.end() && fi->second.first_string) {
                const StrEnt *e = find_str(strs, fi->second.first_string);
                if (e && read_str(img, *e, buf, sizeof buf)) txt = buf;
            }
            fprintf(f, "| `%#x` | `%.70s` |\n", sr, txt);
        }
    }
    fclose(f);
}

void safe_name(char *dst, size_t cap, const char *src);
void write_class_tree(const Image &img, const std::vector<ClassTable> &tables,
                      const std::map<uint32_t, FnAgg> &fns, const std::vector<StrEnt> &strs,
                      const char *root);

bool name_taken(const std::string &name, uint32_t except_start) {
    for (std::map<uint32_t, std::string>::const_iterator it = g_table_class.begin();
         it != g_table_class.end(); ++it)
        if (it->first != except_start && it->second == name) return true;
    for (uint32_t i = 0; i < kDocClassCount; i++)
        if (strcmp(kDocBlob + kDocClasses[i].name, name.c_str()) == 0) return true;
    return false;
}

std::string shape_key(const std::vector<ClassTable> &tables, size_t i) {
    char b[160];
    const uint32_t prev = i ? tables[i - 1].slots : 0;
    const uint32_t next = (i + 1 < tables.size()) ? tables[i + 1].slots : 0;
    snprintf(b, sizeof b, "%s|%u|%u|%u", tables[i].seg.c_str(), prev, tables[i].slots, next);
    return std::string(b);
}

uint32_t name_from_shape_cache(const std::vector<ClassTable> &tables, const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/cache", root);
    mkdir(path, 0755);
    snprintf(path, sizeof path, "%s/cache/shapes.tsv", root);

    std::map<std::string, std::string> known;
    std::set<std::string> ambiguous;
    FILE *f = fopen(path, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof line, f)) {
            char *tab = strchr(line, '\t');
            if (!tab) continue;
            *tab = 0;
            std::string name(tab + 1);
            while (!name.empty() && (name[name.size() - 1] == '\n' || name[name.size() - 1] == '\r'))
                name.erase(name.size() - 1);
            if (name.empty()) continue;
            const std::string key(line);
            std::map<std::string, std::string>::iterator it = known.find(key);
            if (it == known.end()) known[key] = name;
            else if (it->second != name) ambiguous.insert(key);
        }
        fclose(f);
    }

    uint32_t named = 0;
    for (size_t i = 0; i < tables.size(); i++) {
        if (g_table_class.count(tables[i].start)) continue;
        const std::string k = shape_key(tables, i);
        if (ambiguous.count(k)) continue;
        std::map<std::string, std::string>::iterator it = known.find(k);
        if (it == known.end() || name_taken(it->second, tables[i].start)) continue;
        g_table_class[tables[i].start] = it->second;
        g_table_src[tables[i].start] = "shape cache";
        named++;
    }

    f = fopen(path, "w");
    if (f) {
        for (size_t i = 0; i < tables.size(); i++) {
            std::map<uint32_t, std::string>::const_iterator it = g_table_class.find(tables[i].start);
            const char *nm = (it != g_table_class.end()) ? it->second.c_str()
                                                         : family_of_table(tables[i].start);
            if (!nm || !*nm) continue;
            fprintf(f, "%s\t%s\n", shape_key(tables, i).c_str(), nm);
        }
        fclose(f);
    }
    return named;
}

uint32_t name_tables_from_seed(const Image &img, const Layout &L,
                               const std::vector<ClassTable> &tables) {
    uint32_t hits = 0;
    for (size_t i = 0; i < tables.size(); i++) {
        if (name_of_table(tables[i].start)) continue;
        std::map<std::string, uint32_t> votes;
        uint32_t total = 0;
        for (uint32_t s = 0; s < tables[i].slots; s++) {
            uint64_t raw = 0;
            uint32_t sr = 0;
            if (!at(img, img.base + tables[i].start + (uint64_t)s * 8, &raw, sizeof(raw))) break;
            if (!slot_at(img, raw, L.code_lo, L.code_hi, &sr, nullptr)) continue;
            const char *nm = name_for_rva(sr);
            if (nm[0] == '-') continue;
            votes[std::string(class_of(nm))]++;
            total++;
        }
        if (!total) continue;
        std::string best;
        uint32_t bestn = 0;
        for (std::map<std::string, uint32_t>::const_iterator it = votes.begin(); it != votes.end();
             ++it)
            if (it->second > bestn) {
                bestn = it->second;
                best = it->first;
            }
        if (best.empty() || bestn * 2 < total) continue;
        g_table_class[tables[i].start] = best;
        g_table_src[tables[i].start] = "offline seed";
        hits++;
    }
    return hits;
}

void run_deep_scan(const Image &img, const Layout &L, const std::vector<ClassTable> &tables,
                   const char *dump) {
    const char *root = diag_root();
    mkdir(root, 0755);
    ensure_insight(img);
    std::vector<uint32_t> starts;
    if (g_fs && g_fs->v.size() >= 16) starts = g_fs->v;
    else starts = build_starts(img, L);
    if (!g_slot_starts.empty()) {
        starts.insert(starts.end(), g_slot_starts.begin(), g_slot_starts.end());
        std::sort(starts.begin(), starts.end());
        starts.erase(std::unique(starts.begin(), starts.end()), starts.end());
        RCL_LOGLN("[deep] accepted slot entries added to the start set: %zu -> %zu",
                  g_slot_starts.size(), starts.size());
        g_slot_starts.clear();
    }
    std::vector<uint32_t> lcs;
    const bool lcs_ok = lc_function_starts(img, L, lcs);
    std::vector<uint32_t> brs;
    branch_starts(img, L, brs);
    std::vector<uint32_t> alt = lcs;
    alt.insert(alt.end(), brs.begin(), brs.end());
    std::sort(alt.begin(), alt.end());
    alt.erase(std::unique(alt.begin(), alt.end()), alt.end());
    RCL_LOGLN("[deep] starts=%zu source=%s rejected=%u extra=%zu (lc_function_starts=%zu "
              "bl_targets=%zu)",
              starts.size(),
              !g_fs ? "none"
                    : g_fs->from_function_starts ? "LC_FUNCTION_STARTS"
                                                 : g_fs->from_unwind ? "__unwind_info" : "boundary scan",
              g_fs ? g_fs->rejected : 0, alt.size(), lcs_ok ? lcs.size() : 0, brs.size());
    const std::vector<StrEnt> strs = build_strings(img, L);
    SlotMap slots;
    std::vector<uint32_t> tabs;
    for (size_t i = 0; i < tables.size(); i++) tabs.push_back(tables[i].start);
    std::sort(tabs.begin(), tabs.end());
    tabs.erase(std::unique(tabs.begin(), tabs.end()), tabs.end());
    slots.sorted.reserve(32768);
    slots.table_of.reserve(32768);
    for (size_t i = 0; i < tables.size(); i++)
        for (uint32_t s = 0; s < tables[i].slots; s++) {
            uint64_t raw = 0;
            if (!at(img, img.base + tables[i].start + (uint64_t)s * 8, &raw, 8)) break;
            add_slot(slots, (uint32_t)((raw & 0xFFFFFFFFFULL) - img.base), tables[i].start);
        }
    finish_slot_map(slots);
    std::map<uint32_t, FnAgg> fns;
    code_pass(img, L, starts, alt, strs, slots, tabs, fns);
    std::vector<GlobalHit> gh;
    scan_globals(img, L, tables, gh);
    data_refs(img, L, tabs);
    expand_calls(fns);
    uint32_t merge_cand = 0;
    const uint32_t merged = merge_runs(img, tables, starts, &merge_cand);
    const uint32_t dup = dup_tables(img, tables);
    live_census(img, tabs);
    RCL_LOGLN("[deep] refs=%zu ctor_installs=%zu live_tables=%zu merged=%u of %u dup=%u",
              g_table_ref.size(), g_ctor_table.size(), g_table_inst.size(), merged, merge_cand, dup);
    build_unique_strings();
    RCL_LOGLN("[deep] class-specific reference strings: %zu", g_unique_str.size());
    uint32_t str_fns = 0;
    for (std::map<uint32_t, FnAgg>::const_iterator it = fns.begin(); it != fns.end(); ++it)
        if (it->second.first_string) str_fns++;
    name_tables_from_strings(img, strs, tables, fns);
    uint32_t method_named = 0;
    name_from_method_index(img, tables, &method_named, root);
    const uint32_t seeded = name_tables_from_seed(img, L, tables);
    uint32_t families = 0;
    cluster_families(img, tables, root, &families);
    const uint32_t shape_named = name_from_shape_cache(tables, root);
    RCL_LOGLN("[deep] shape cache carried %u names from an earlier run", shape_named);
    write_strings(img, strs, fns, root);
    write_fields(fns, root);
    write_all_offsets(tables, slots, fns, gh, root);
    uint32_t tu = 0;
    tu_cluster(img, tables, &tu);
    std::vector<Sandw> sw;
    uint32_t blocks = 0, ordered = 0;
    sandwiches(tables, sw, &blocks, &ordered);
    write_order_hint(tables, root, sw);
    RCL_LOGLN("[deep] order blocks=%u alphabetically ordered=%u", blocks, ordered);
    std::vector<RegPair> reg;
    scan_registry(img, L, tables, reg);
    write_registry(reg, root);
    write_confidence(tables, root, merged, merge_cand, dup);
    external_align(root);
    import_foreign_names(img, root);
    write_table_names(tables, root);
    write_unknown_named(img, strs, tables, fns, root);
    write_globals(gh, img, root);
    write_anchors_extra(tables, root);
    g_deep.starts = (uint32_t)starts.size();
    g_deep.strings = (uint32_t)strs.size();
    g_deep.anchored = str_fns;
    g_deep.globals = (uint32_t)gh.size();
    g_deep.named = (uint32_t)g_table_class.size();
    g_deep.tables = (uint32_t)tables.size();
    g_deep.slots = (uint32_t)slots.sorted.size();
    g_deep.method_named = method_named;
    g_deep.seeded = seeded;
    g_deep.families = families;
    g_deep.registry = (uint32_t)reg.size();
    g_deep.tu_clustered = tu;
    g_deep.sandwiched = 0;
    for (size_t i = 0; i < sw.size(); i++) g_deep.sandwiched += (uint32_t)sw[i].vts.size();
    RCL_LOGLN("[deep] starts=%zu strings=%zu slots=%zu str_fns=%u globals=%zu tables=%zu "
              "named=%zu method_index=%u seeded=%u families=%u registry=%zu sandwiched=%u",
               starts.size(), strs.size(), slots.sorted.size(), str_fns, gh.size(), tables.size(),
               g_table_class.size(), method_named, seeded, families, reg.size(), g_deep.sandwiched);

    if (g_mi && g_fs) {
        DeepStats ds;
        ds.fstarts_source = g_fs->from_function_starts ? 1 : (g_fs->from_unwind ? 2 : 3);
        ds.fstarts = (uint32_t)g_fs->v.size();
        ds.fstarts_rejected = g_fs->rejected;
        ds.data_in_code = (uint32_t)g_datacode.size();
        const char *uuid = g_mi->uuid;
        deep_macho_report(img, *g_mi, *g_fs, g_datacode, root, ds);
        deep_objc(img, *g_mi, root, ds);
        deep_mangled(img, *g_mi, root, ds);
        deep_fieldmap(img, *g_mi, *g_fs, root, ds);
        deep_accessors(img, *g_mi, *g_fs, tables, root, ds);
        deep_functions(img, *g_mi, *g_fs, tables, root, ds);
        deep_export(img, *g_mi, *g_fs, tables, root, ds);
        deep_globals(img, *g_mi, *g_fs, tables, root, ds);
        deep_logic(root, ds);
        deep_heap(img, *g_mi, *g_fs, root, ds);
        std::vector<ClassTable> extra;
        deep_indirect(img, *g_mi, *g_fs, extra, ds);
        std::map<uint32_t, std::string> carried;
        deep_cache_load(root, uuid, carried, ds);
        std::map<uint32_t, std::string> order_out;
        deep_order(img, *g_mi, tables, g_table_class, root, order_out, ds);
        deep_fingerprints(img, *g_mi, *g_fs, tables, g_table_class, root, carried, ds);
        CandMap cand;
        for (std::map<uint32_t, std::string>::const_iterator it = order_out.begin();
             it != order_out.end(); ++it)
            if (!g_table_class.count(it->first)) cand[it->first] = std::make_pair(it->second, "order");
        for (std::map<uint32_t, std::string>::const_iterator it = carried.begin();
             it != carried.end(); ++it)
            if (!g_table_class.count(it->first) && !cand.count(it->first))
                cand[it->first] = std::make_pair(it->second, "fingerprint");
        commit_names(cand);
        if (!extra.empty()) {
            char p[1024];
            snprintf(p, sizeof p, "%s/_indirect.md", root);
            FILE *f = fopen(p, "w");
            if (f) {
                fprintf(f, "# tables reached only through an indexed or offset load of a table base\n\n");
                fprintf(f, "| table rva | slots | segment |\n|-----------|-------|---------|\n");
                for (size_t i = 0; i < extra.size(); i++)
                    fprintf(f, "| `%#x` | %u | %s |\n", extra[i].start, extra[i].slots,
                            extra[i].seg.c_str());
                fclose(f);
            }
        }
        deep_cache_save(root, uuid, g_table_class);
        write_class_tree(img, tables, fns, strs, dump);
        write_deep_summary(*g_mi, root, ds);
        RCL_LOGLN("[deep] extra: objc=%u mangled=%u loaders=%u indirect=%u heap_tables=%u order=%u "
                  "fp_carried=%u cache=%u",
                  ds.objc_classes, ds.mangled_found, ds.loaders, ds.indirect_added, ds.heap_tables,
                  ds.order_named, ds.fp_named, ds.cache_names);
        RCL_LOGLN("[deep] accessors: getters=%u setters=%u with_class=%u", ds.getters, ds.setters,
                  ds.accessors_owned);
    }
    g_deep_ready = true;
}

void write_class_tree(const Image &img, const std::vector<ClassTable> &tables,
                      const std::map<uint32_t, FnAgg> &fns, const std::vector<StrEnt> &strs,
                      const char *root) {
    mkdir(root, 0755);
    char dir[1024];
    char path[1200];
    char buf[512];
    std::map<std::string, uint32_t> per_cat;
    uint32_t written = 0;
    RCL_LOGLN("[tree] root=%s tables=%zu named=%zu family=%zu first=%#x",
              root, tables.size(), g_table_class.size(), g_table_family.size(),
              tables.empty() ? 0 : tables[0].start);
    for (size_t i = 0; i < tables.size(); i++) {
        const ClassTable &t = tables[i];
        const char *nm = name_of_table(t.start);
        const char *fam = (!nm || !*nm) ? family_of_table(t.start) : nullptr;
        if (!nm && !fam) {
            per_cat["Unknown"]++;
            continue;
        }
        std::string label = (nm && *nm) ? std::string(nm) : std::string(fam);
        if (!nm || !*nm) label += "." + hex_label(t.start).substr(3);
        const char *cat = category_of_name(label.c_str());
        char safe[192];
        safe_name(safe, sizeof safe, label.c_str());
        if (!*safe) snprintf(safe, sizeof safe, "%s", "vt");
        snprintf(dir, sizeof dir, "%s/%s", root, cat);
        mkdir(dir, 0755);
        snprintf(path, sizeof path, "%s/%s.md", dir, safe);

        FILE *probe = fopen(path, "r");
        if (probe) {
            fclose(probe);
            g_tree_written.insert(t.start);
            per_cat[cat]++;
            continue;
        }
        FILE *f = fopen(path, "w");
        if (!f) continue;
        fprintf(f, "# %s\n\n**Folder:** %s\n**Class Table:** `%#x`  **Slots:** %u  "
                   "**Segment:** `%s`\n\n## Methods\n\n"
                   "| slot | rva | address | name | string this function uses |\n"
                   "|------|-----|---------|------|---------------------------|\n",
                label.c_str(), cat, t.start, t.slots, t.seg.c_str());
        for (uint32_t s = 0; s < t.slots; s++) {
            uint64_t raw = 0;
            if (!at(img, img.base + t.start + (uint64_t)s * 8, &raw, sizeof raw)) break;
            const uint32_t sr = (uint32_t)((raw & 0xFFFFFFFFFULL) - img.base);
            std::map<uint32_t, FnAgg>::const_iterator fi = fns.find(sr);
            const char *txt = "-";
            if (fi != fns.end() && fi->second.first_string) {
                const StrEnt *e = find_str(strs, fi->second.first_string);
                if (e && read_str(img, *e, buf, sizeof buf)) txt = buf;
            }
            fprintf(f, "| `+0x%03x` | `%#x` | `%#llx` | %s | `%.70s` |\n", s * 8, sr,
                    (unsigned long long)(img.base + sr), name_for_rva(sr), txt);
        }
        std::map<uint32_t, uint32_t> off;
        for (std::map<uint32_t, FnAgg>::const_iterator it = fns.begin(); it != fns.end(); ++it)
            if (it->second.table == t.start)
                for (size_t k = 0; k < it->second.fields.size(); k++) off[it->second.fields[k]]++;
        fprintf(f, "\n## Field candidates\n\n| offset | hits |\n|--------|------|\n");
        if (off.empty()) fprintf(f, "| - | - |\n");
        for (std::map<uint32_t, uint32_t>::const_iterator it = off.begin(); it != off.end(); ++it)
            fprintf(f, "| `%#x` | %u |\n", it->first, it->second);
        fclose(f);
        g_tree_written.insert(t.start);
        written++;
        per_cat[cat]++;
    }

    snprintf(path, sizeof path, "%s/INDEX.md", diag_root());
    FILE *ix = fopen(path, "w");
    if (ix) {
        fprintf(ix, "# classes and their tables, laid out into folders\n\n");
        fprintf(ix, "| folder | class files |\n|--------|-------------|\n");
        for (std::map<std::string, uint32_t>::const_iterator it = per_cat.begin();
             it != per_cat.end(); ++it)
            fprintf(ix, "| `%s` | %u |\n", it->first.c_str(), it->second);
        fprintf(ix, "\nclass tables %zu, files created %u, unclaimed tables live in `Unknown/`\n",
                tables.size(), written);
        fclose(ix);
    }
    RCL_LOGLN("[deep] folders: %zu, files created %u, tables %zu", per_cat.size(), written,
              tables.size());
}

}  // namespace

void dump_class_tree(const Image &img) {
    live_boot(img);
    const char *mode = getenv("RCL_CLASSES");
    if (mode && *mode == '0') return;

    Layout L;
    layout(img, L);
    RCL_LOGLN("[classes] hdr=%s nsegs=%d code=%#llx..%#llx data_segs=%d image=%#llx+%#llx",
              L.hdr ? "ok" : "FAIL", L.nsegs, (unsigned long long)L.code_lo,
              (unsigned long long)L.code_hi, L.data_n, (unsigned long long)img.base,
              (unsigned long long)img.image_vmsize);
    for (int i = 0; i < L.data_n && i < 8; i++)
        RCL_LOGLN("   seg %-16s %#llx..%#llx", L.data[i].name,
                  (unsigned long long)L.data[i].start, (unsigned long long)L.data[i].end);

    const std::vector<ClassTable> t = scan_class_tables(img);
    const bool full = mode && strcmp(mode, "full") == 0;
    uint64_t slots = 0, named = 0;
    for (const ClassTable &c : t) {
        slots += c.slots;
        named += c.named;
    }
    RCL_LOGLN("[classes] tables=%zu slots=%llu named_slots=%llu  (every class table in the image)",
              t.size(), (unsigned long long)slots, (unsigned long long)named);
    run_deep_scan(img, L, t, dump_root());

    if (!full) {
        for (const ClassTable &c : t)
            RCL_LOGLN("  vt=0x%06x slots=%3u named=%3u seg=%s", c.start, c.slots, c.named,
                      c.seg.c_str());
        return;
    }

    uint32_t index = 0;
    for (const ClassTable &c : t) {
        char label[96];
        uint32_t votes = 0;
        label[0] = '-';
        label[1] = 0;
        for (uint32_t s = 0; s < c.slots; s++) {
            uint64_t raw = 0;
            uint32_t sr = 0;
            if (!at(img, img.base + c.start + s * 8, &raw, sizeof(raw))) break;
            if (!slot_at(img, raw, L.code_lo, L.code_hi, &sr, nullptr)) continue;
            const char *nm = name_for_rva(sr);
            if (nm[0] == '-') continue;
            if (label[0] == '-') snprintf(label, sizeof(label), "%s", class_of(nm));
            if (strcmp(class_of(nm), label) != 0) continue;
            votes++;
        }
        RCL_LOGLN("[class %3u] vt=0x%06x slots=%3u named=%3u votes=%3u seg=%s %s",
                  index++, c.start, c.slots, c.named, votes, c.seg.c_str(), label);
        for (uint32_t s = 0; s < c.slots; s++) {
            uint64_t raw = 0;
            uint32_t sr = 0;
            if (!at(img, img.base + c.start + s * 8, &raw, sizeof(raw))) break;
            if (!slot_at(img, raw, L.code_lo, L.code_hi, &sr, nullptr)) {
                RCL_LOGLN("    +0x%03x  ----------  -", s * 8);
                continue;
            }
            RCL_LOGLN("    +0x%03x  0x%06x  %s", s * 8, sr, name_for_rva(sr));
        }
    }
    RCL_LOGLN("[classes] end tables=%zu slots=%llu named_slots=%llu", t.size(),
              (unsigned long long)slots, (unsigned long long)named);
}

std::vector<ClassBoundary> discover_class_boundaries(const Image &img) {
    std::vector<ClassBoundary> out;
    const std::vector<ClassTable> t = scan_class_tables(img);
    for (size_t i = 0; i < t.size(); i++) {
        ClassBoundary b;
        b.start = t[i].start;
        b.slots = t[i].slots;
        b.name = name_of_table(t[i].start);
        out.push_back(b);
    }
    std::sort(out.begin(), out.end(),
              [](const ClassBoundary &x, const ClassBoundary &y) { return x.start < y.start; });
    return out;
}




namespace {

const char *blob_at(uint32_t off) { return kDocBlob + off; }

struct SlotName {
    uint32_t rva;
    uint32_t method;
};

struct DocIndex {
    std::vector<SlotName> by_rva;
    std::vector<ClassTable> tables;

    const char *method_for(uint32_t rva) const {
        uint32_t lo = 0, hi = (uint32_t)by_rva.size();
        while (lo < hi) {
            uint32_t mid = (lo + hi) / 2;
            if (by_rva[mid].rva == rva) return blob_at(kDocMethods[by_rva[mid].method].sig);
            if (by_rva[mid].rva < rva) lo = mid + 1; else hi = mid;
        }
        return "-";
    }

    const ClassTable *table_at(uint32_t vt) const {
        for (const ClassTable &t : tables)
            if (t.start == vt) return &t;
        return nullptr;
    }
};

bool entry_ok(uint32_t w) {
    if (w == 0xD503233Fu || w == 0xD503237Fu || w == 0xD65F03C0u || w == 0xD503201Fu) return true;
    if ((w & 0xFFFFFF1Fu) == 0xD503241Fu) return true;
    if ((w & 0xFF800000u) == 0xA9800000u && ((w >> 5) & 31u) == 31u) return true;
    if ((w & 0xFF800000u) == 0xA9000000u && ((w >> 5) & 31u) == 31u) return true;
    if ((w & 0xFFC003FFu) == 0xD10003FFu) return true;
    if ((w & 0xFF8003FFu) == 0xD10003FFu) return true;
    if ((w & 0xFFFFFFE0u) == 0x910003E0u) return true;
    if ((w & 0xFFFFFC1Fu) == 0xD4200000u) return true;
    if ((w & 0xFC000000u) == 0x14000000u) return true;
    return false;
}

bool live_ok(const Image &img, uint32_t rva) {
    uint32_t w = 0;
    if (img.vmsize == 0 || rva >= img.vmsize) return false;
    if (!img.read || !img.read(img.ctx, img.base + rva, &w, sizeof(w))) return false;
    return entry_ok(w);
}

void mkdir_one(const char *path) {
    mkdir(path, 0755);
}

void safe_name(char *dst, size_t cap, const char *src) {
    size_t i = 0;
    for (; src[i] && i + 1 < cap; i++) dst[i] = (src[i] == '/' || src[i] == '\\') ? '_' : src[i];
    dst[i] = 0;
}

void print_hints(FILE *f, const char *hints) {
    const char *p = hints;
    while (p && *p) {
        const char *e = strchr(p, '\x1f');
        int n = e ? (int)(e - p) : (int)strlen(p);
        fprintf(f, "  - %.*s\n", n, p);
        if (!e) break;
        p = e + 1;
    }
}

}  // namespace

void write_class_docs(const Image &img) {
    const char *mode = getenv("RCL_DOCS");
    if (mode && *mode == '0') return;

    char root[512];
    snprintf(root, sizeof root, "%s", dump_root());
    mkdir_one(root);
    char path[1024];
    snprintf(path, sizeof path, "%s/Unknown", root);
    mkdir_one(path);

    DocIndex ix;
    ScanStats st;
    ix.tables = scan_class_tables(img, &st);
    ix.by_rva.reserve(kDocMethodCount);
    for (uint32_t i = 0; i < kDocMethodCount; i++)
        ix.by_rva.push_back({kDocMethods[i].rva, i});
    std::sort(ix.by_rva.begin(), ix.by_rva.end(),
              [](const SlotName &a, const SlotName &b) { return a.rva < b.rva; });

    uint32_t probe_all = 0, probe_ok = 0;
    for (uint32_t i = 0; i < kDocMethodCount; i++) {
        probe_all++;
        uint32_t w = 0;
        if (img.read && img.read(img.ctx, img.base + kDocMethods[i].rva, &w, sizeof w) && entry_ok(w))
            probe_ok++;
    }
    const bool ref_match = probe_all == 0 || (uint64_t)probe_ok * 4 >= (uint64_t)probe_all * 3;
    if (!ref_match)
        RCL_LOGLN("[ref] reference hits %u/%u method addresses, image looks like a different "
                  "build: reference names are unreliable",
                  probe_ok, probe_all);

    std::vector<uint32_t> claimed;
    char cat[128];
    char cls[128];
    uint32_t files = 0;
    uint32_t methods_ok = 0;
    uint32_t methods_all = 0;

    for (uint32_t c = 0; c < kDocClassCount; c++) {
        const DocClass &d = kDocClasses[c];
        safe_name(cat, sizeof cat, blob_at(d.cat));
        safe_name(cls, sizeof cls, blob_at(d.name));
        snprintf(path, sizeof path, "%s/%s", root, cat);
        mkdir_one(path);
        snprintf(path, sizeof path, "%s/%s/%s.md", root, cat, cls);
        FILE *f = fopen(path, "w");
        if (!f) continue;

        uint32_t vt = d.vt;
        if (!vt) {
            const char *nm = blob_at(d.name);
            for (std::map<uint32_t, std::string>::const_iterator it = g_table_class.begin();
                 it != g_table_class.end(); ++it)
                if (it->second == nm) {
                    vt = it->first;
                    break;
                }
        }
        const ClassTable *t = vt ? ix.table_at(vt) : nullptr;
        if (t) claimed.push_back(t->start);

        fprintf(f, "# %s\n\n**Function Count:** %u\n**Class:** `%s`\n", cls, d.count, cls);
        if (t) fprintf(f, "**Class Table:** `%#x` (%u slots)\n", t->start, t->slots);

        fprintf(f, "\n## Key String Signatures\n\nThese strings can be used to identify class "
                   "methods in a stripped binary via `data_ref` searches:\n\n");
        const char *sp = blob_at(d.strings);
        if (!*sp) fprintf(f, "- (none)\n");
        while (*sp) {
            const char *e = strchr(sp, '\x1f');
            int n = e ? (int)(e - sp) : (int)strlen(sp);
            fprintf(f, "- `%.*s`\n", n, sp);
            if (!e) break;
            sp = e + 1;
        }

        fprintf(f, "\n## Method Index\n\n| # | Method | Address | Size | Signature |\n"
                   "|---|--------|---------|------|-----------|\n");
        for (uint16_t k = 0; k < d.count; k++) {
            const DocMethod &m = kDocMethods[d.first + k];
            const char *sig = blob_at(m.sig);
            const char *nm = strstr(sig, "::");
            fprintf(f, "| %u | `%s` | `%#llx` | %u | `%s` |\n", k + 1,
                    nm ? nm + 2 : sig, (unsigned long long)(img.base + m.rva), m.size, sig);
        }

        fprintf(f, "\n## Method Details\n");
        for (uint16_t k = 0; k < d.count; k++) {
            const DocMethod &m = kDocMethods[d.first + k];
            const char *sig = blob_at(m.sig);
            const char *nm = strstr(sig, "::");
            methods_all++;
            if (live_ok(img, m.rva)) methods_ok++;
            fprintf(f, "\n### %u. `%s`\n\n- **Address:** `%#llx`\n- **RVA:** `%#x`\n"
                       "- **Mangled:** `%s`\n- **Signature:** `%s`\n- **Size:** %u bytes\n"
                       "- **Live:** %s\n", k + 1, nm ? nm + 2 : sig,
                    (unsigned long long)(img.base + m.rva), m.rva, blob_at(m.mangled), sig, m.size,
                    live_ok(img, m.rva) ? "ok" : "stale");
            const char *hints = blob_at(m.hints);
            if (*hints) {
                fprintf(f, "- **Identification Hints:**\n");
                print_hints(f, hints);
            }
        }

        const char *notes = blob_at(d.notes);
        if (*notes) fprintf(f, "\n## Class Identification Notes\n\n%s\n", notes);

        if (t) {
            fprintf(f, "\n## Class Table\n\n**Table:** `%#x`  **Slots:** %u  "
                       "**Segment:** `%s`\n\n| slot | rva | address | method |\n"
                       "|------|-----|---------|--------|\n", t->start, t->slots, t->seg.c_str());
            for (uint32_t s = 0; s < t->slots; s++) {
                uint64_t raw = 0;
                uint32_t sr = 0;
                if (!img.read || !img.read(img.ctx, img.base + t->start + s * 8, &raw, sizeof(raw)))
                    break;
                sr = (uint32_t)((raw & 0xFFFFFFFFFULL) - img.base);
                const char *nm = ix.method_for(sr);
                if (nm[0] == '-') nm = name_for_rva(sr);
                fprintf(f, "| `+0x%03x` | `%#x` | `%#llx` | %s |\n", s * 8, sr,
                        (unsigned long long)(img.base + sr), nm);
            }
        }

        fclose(f);
        files++;
    }

    uint32_t unknown = 0;
    for (const ClassTable &t : ix.tables) {
        if (std::find(claimed.begin(), claimed.end(), t.start) != claimed.end()) continue;
        if (g_tree_written.count(t.start)) continue;
        snprintf(path, sizeof path, "%s/Unknown/vt_%06x.md", root, t.start);
        FILE *f = fopen(path, "w");
        if (!f) continue;
        std::map<uint32_t, std::string>::const_iterator gu = g_table_class.find(t.start);
        const char *gu_fam = (gu == g_table_class.end()) ? family_of_table(t.start) : nullptr;
        std::string title = hex_label(t.start);
        if (gu != g_table_class.end() && !gu->second.empty()) title += " - " + gu->second;
        if (gu_fam && *gu_fam) title += " - " + std::string(gu_fam);
        fprintf(f, "# %s\n\n**Class Table:** `%#x`  **Slots:** %u  **Segment:** `%s`\n\n"
                   "| slot | rva | address | name |\n|------|-----|---------|------|\n",
                title.c_str(), t.start, t.slots, t.seg.c_str());
        for (uint32_t s = 0; s < t.slots; s++) {
            uint64_t raw = 0;
            if (!img.read || !img.read(img.ctx, img.base + t.start + s * 8, &raw, sizeof(raw))) break;
            uint32_t sr = (uint32_t)((raw & 0xFFFFFFFFFULL) - img.base);
            const char *nm = ix.method_for(sr);
            if (nm[0] == '-') nm = name_for_rva(sr);
            fprintf(f, "| `+0x%03x` | `%#x` | `%#llx` | %s |\n", s * 8, sr,
                    (unsigned long long)(img.base + sr), nm);
        }
        fclose(f);
        unknown++;
    }

    snprintf(path, sizeof path, "%s/_diag.md", diag_root());
    FILE *dg = fopen(path, "w");
    if (dg) {
        fprintf(dg, "# recoil dump diagnostics\n\n");
        fprintf(dg, "- base `%#llx`  text_vmsize `%#llx`  image_vmsize `%#llx`\n",
                (unsigned long long)img.base, (unsigned long long)img.vmsize,
                (unsigned long long)img.image_vmsize);
        fprintf(dg, "- slide `%#llx` (load commands hold static addresses; base - __TEXT vmaddr)\n",
                (unsigned long long)st.slide);
        fprintf(dg, "- header %s  magic `%#x`  ncmds %u  data segments %u\n",
                st.hdr_ok ? "parsed" : "FAIL", st.magic, st.ncmds, (unsigned)st.segs.size());
        for (const SegInfo &si : st.segs)
            fprintf(dg, "- scanned segment `%s`  `%#llx`..`%#llx`\n", si.name,
                    (unsigned long long)si.start, (unsigned long long)si.end);
        fprintf(dg, "- code range `%#llx`..`%#llx`\n", (unsigned long long)img.base,
                (unsigned long long)(img.base + img.vmsize));
        fprintf(dg, "- words %llu  pointers into code %llu  valid entries %llu  entry rejects %llu\n",
                (unsigned long long)st.words, (unsigned long long)st.ptr_ok,
                (unsigned long long)st.entry_ok, (unsigned long long)st.entry_rej);
        if (st.sample_reason)
            fprintf(dg, "- first rejected candidate: raw `%#x` -> rva `%#x`\n", st.sample_raw,
                    st.sample_rva);
        fprintf(dg, "- tables %zu (strict %u, loose %u, loose words %llu)  class files %u  "
                    "table files %u\n", ix.tables.size(), st.tables_strict, st.tables_loose,
                (unsigned long long)st.loose_words, files, unknown);
        fprintf(dg, "- deep: starts %u strings %u functions with a string %u globals %u "
                    "tables %u\n",
                g_deep.starts, g_deep.strings, g_deep.anchored, g_deep.globals, g_deep.tables);
        fprintf(dg, "- names: total %u of %u | method index %u | offline seed %u | families %u | "
                    "order constrained %u | registry pairs %u | tu clustered %u\n",
                g_deep.named, g_deep.tables, g_deep.method_named, g_deep.seeded, g_deep.families,
                g_deep.sandwiched, g_deep.registry, g_deep.tu_clustered);
        fprintf(dg, "- reference method addresses: %u/%u match%s\n", probe_ok, probe_all,
                ref_match ? "" : " (different build, names unreliable)");
        fclose(dg);
    }

    RCL_LOGLN("[docs] wrote %u class files + %u table files to %s  (method addresses live: %u/%u)",
              files, unknown, root, methods_ok, methods_all);
    RCL_LOGLN("[docs] classes=%u methods=%u tables=%zu", kDocClassCount, kDocMethodCount,
              ix.tables.size());
}

static bool bundle_ext_ok(const char *name) {
    size_t n = strlen(name);
    if (n > 4 && strcmp(name + n - 4, ".tsv") == 0) return true;
    if (n > 3 && strcmp(name + n - 3, ".md") == 0) return true;
    return false;
}

static bool bundle_copy(const char *src, const char *dst) {
    FILE *a = fopen(src, "rb");
    if (!a) return false;
    FILE *b = fopen(dst, "wb");
    if (!b) {
        fclose(a);
        return false;
    }
    char buf[16384];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof buf, a)) > 0)
        if (fwrite(buf, 1, n, b) != n) {
            fclose(a);
            fclose(b);
            return false;
        }
    fclose(a);
    fclose(b);
    return true;
}

static bool g_skip_bundle = false;

void set_skip_bundle(bool skip) { g_skip_bundle = skip; }

void write_all_bundle() {
    if (g_skip_bundle) return;
    const char *mode = getenv("RCL_DOCS");
    if (mode && *mode == '0') return;

    char root[512];
    snprintf(root, sizeof root, "%s", dump_root());
    char all[1024];
    snprintf(all, sizeof all, "%s/All", root);
    mkdir_one(all);

    DIR *d = opendir(root);
    if (!d) return;
    uint32_t copied = 0;
    struct dirent *e = nullptr;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        if (strcmp(e->d_name, "All") == 0 || strcmp(e->d_name, "cache") == 0) continue;
        char sub[2048];
        snprintf(sub, sizeof sub, "%s/%s", root, e->d_name);
        struct stat sb;
        if (stat(sub, &sb) != 0) continue;
        if (!S_ISDIR(sb.st_mode)) {
            if (!bundle_ext_ok(e->d_name)) continue;
            char dst[2048];
            snprintf(dst, sizeof dst, "%s/%s", all, e->d_name);
            if (bundle_copy(sub, dst)) copied++;
            continue;
        }
        DIR *sd = opendir(sub);
        if (!sd) continue;
        struct dirent *se = nullptr;
        while ((se = readdir(sd))) {
            if (se->d_name[0] == '.') continue;
            if (!bundle_ext_ok(se->d_name)) continue;
            char src[2048];
            char dst[2048];
            snprintf(src, sizeof src, "%s/%s", sub, se->d_name);
            snprintf(dst, sizeof dst, "%s/%s_%s", all, e->d_name, se->d_name);
            if (bundle_copy(src, dst)) copied++;
        }
        closedir(sd);
    }
    closedir(d);
    RCL_LOGLN("[docs] All: %u files in %s", copied, all);
}




namespace {

const uint32_t kObjMax = 1024;

struct Obs {
    uint32_t vt = 0;
    uint32_t state_mask = 0;
    uint32_t hits = 0;
    uint32_t slots = 0;
    int first_tick = 0;
};

std::map<uint32_t, Obs> g_obs;
int g_last_state = -1;
int g_ticks = 0;
uint32_t g_last_home = 0;
uint32_t g_last_cur = 0;
uint32_t g_last_mgr = 0;
uint32_t g_last_elem_vt = 0;
uint32_t g_elem_count = 0;
uint32_t g_elem_cap = 0;

bool rd(const Image &img, uint64_t va, void *dst, size_t n) {
    return img.read && img.read(img.ctx, va, dst, n);
}

bool rd64(const Image &img, uint64_t va, uint64_t &out) { return rd(img, va, &out, 8) && out; }
bool rd32(const Image &img, uint64_t va, uint32_t &out) { return rd(img, va, &out, 4) && out; }

uint32_t rva_of(const Image &img, uint64_t va) {
    if (va < img.base) return 0;
    uint64_t r = va - img.base;
    if (r == 0 || r >= (img.image_vmsize ? img.image_vmsize : 0x1200000)) return 0;
    return (uint32_t)r;
}

const char *ref_name(uint32_t vt) {
    for (uint32_t i = 0; i < kDocClassCount; i++)
        if (kDocClasses[i].vt == vt) return kDocBlob + kDocClasses[i].name;
    return "-";
}

const std::vector<ClassTable> &tables(const Image &img) {
    static std::vector<ClassTable> t;
    static bool built = false;
    if (!built) {
        t = scan_class_tables(img, nullptr);
        built = true;
    }
    return t;
}

uint32_t slots_of(const Image &img, uint32_t vt) {
    for (const ClassTable &t : tables(img))
        if (t.start == vt) return t.slots;
    return 0;
}

void observe(const Image &img, uint64_t va, uint32_t state, int tick) {
    uint64_t v = 0;
    if (!rd64(img, va, v)) return;
    uint32_t vt = rva_of(img, v & 0xFFFFFFFFFULL);
    if (!vt) return;
    Obs &o = g_obs[vt];
    if (!o.vt) {
        o.vt = vt;
        o.slots = slots_of(img, vt);
        o.first_tick = tick;
    }
    o.state_mask |= 1u << (state & 31);
    o.hits++;
}

void mkdir_p(const char *path) { mkdir(path, 0755); }

void write_observed(const Image &img, const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_live", root);
    mkdir_p(path);
    snprintf(path, sizeof path, "%s/_live/observed.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# observed classes (every vtable that was live on the heap)\n\n");
    fprintf(f, "- ticks seen %d  distinct vtables %zu  image tables %zu\n", g_ticks, g_obs.size(),
            tables(img).size());
    fprintf(f, "- last home `%#x`  current `%#x`  manager `%#x`  elements %u/%u\n", g_last_home,
            g_last_cur, g_last_mgr, g_elem_count, g_elem_cap);
    fprintf(f, "\n| vtable | slots | states | hits | first tick | reference class |\n");
    fprintf(f, "|--------|-------|--------|------|-----------|-----------------|\n");
    for (const auto &kv : g_obs) {
        const Obs &o = kv.second;
        char st[64] = "";
        for (int b = 0; b < 32; b++)
            if (o.state_mask & (1u << b)) {
                char one[8];
                snprintf(one, sizeof one, "%s%d", st[0] ? "," : "", b);
                strncat(st, one, sizeof(st) - strlen(st) - 1);
            }
        fprintf(f, "| `%#x` | %u | %s | %u | %d | %s |\n", o.vt, o.slots, st, o.hits, o.first_tick,
                ref_name(o.vt));
    }

    for (int state = 0; state < 32; state++) {
        bool any = false;
        for (const auto &kv : g_obs)
            if (kv.second.state_mask & (1u << state)) any = true;
        if (!any) continue;
        snprintf(path, sizeof path, "%s/_live/state_%d.md", root, state);
        FILE *g = fopen(path, "w");
        if (!g) continue;
        fprintf(g, "# state %d observed classes\n\n| vtable | slots | hits | first tick | class |\n"
                   "|--------|-------|------|-----------|-------|\n", state);
        for (const auto &kv : g_obs) {
            const Obs &o = kv.second;
            if (!(o.state_mask & (1u << state))) continue;
            fprintf(g, "| `%#x` | %u | %u | %d | %s |\n", o.vt, o.slots, o.hits, o.first_tick,
                    ref_name(o.vt));
        }
        fclose(g);
    }

    snprintf(path, sizeof path, "%s/_live/anchors.md", root);
    FILE *a = fopen(path, "w");
    if (!a) return;
    uint64_t slot = 0;
    uint32_t so = 0, co = 0, mo = 0, ao = 0, cao = 0, cno = 0;
    const bool have = live_chain(img, slot, so, co, mo, ao, cao, cno);
    fprintf(a, "# anchors seen live (RVAs worth keeping)\n\n");
    if (!have) fprintf(a, "- singleton chain not discovered\n\n");
    fprintf(a, "| what | offset / global | value seen |\n|------|------------------|------------|\n");
    fprintf(a, "| home singleton | `BASE+%#llx` | `%#x` |\n", (unsigned long long)slot, g_last_home);
    fprintf(a, "| state | `home+%#x` | - |\n", so);
    fprintf(a, "| current | `home+%#x` | `%#x` |\n", co, g_last_cur);
    fprintf(a, "| manager | `current+%#x` | `%#x` |\n", mo, g_last_mgr);
    fprintf(a, "| array | `manager+%#x` | - |\n", ao);
    fprintf(a, "| count | `manager+%#x` | %u |\n", cno, g_elem_count);
    fprintf(a, "| capacity | `manager+%#x` | %u |\n", cao, g_elem_cap);
    fprintf(a, "| element vtable | `element+0x0` | `%#x` |\n", g_last_elem_vt);
    fprintf(a, "\nmanager elements: %u live of %u capacity\n", g_elem_count, g_elem_cap);
    fclose(a);
}

void write_missing(const Image &img, const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_missing.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    const std::vector<ClassTable> &t = tables(img);
    uint64_t slots = 0, named = 0;
    uint32_t missing_tables = 0, missing_live = 0;
    for (const ClassTable &c : t) {
        slots += c.slots;
        named += c.named;
        if (strcmp(ref_name(c.start), "-") == 0) missing_tables++;
    }
    fprintf(f, "# what is missing from the class reference\n\n");
    if (!g_deep_ready)
        fprintf(f, "- deep scan: not run yet in this session\n");
    else
        fprintf(f, "- deep scan: starts %u strings %u anchored functions %u globals %u tables named "
                   "from strings %u of %u\n", g_deep.starts, g_deep.strings, g_deep.anchored,
                g_deep.globals, g_deep.named, g_deep.tables);
    uint32_t by_string = 0;
    for (std::map<uint32_t, std::string>::const_iterator it = g_table_class.begin();
         it != g_table_class.end(); ++it)
        if (strcmp(doc_class_name(it->first), "-") == 0) by_string++;
    fprintf(f, "- tables named ONLY by their strings (not in the reference): %u\n", by_string);
    fprintf(f, "- tables in image %zu  slots %llu  slots with a known method %llu\n", t.size(),
            (unsigned long long)slots, (unsigned long long)named);
    fprintf(f, "- tables without a reference class: %u\n", missing_tables);
    fprintf(f, "- methods documented %u  methods found in a table: (see _diag.md)\n", kDocMethodCount);
    fprintf(f, "- observed vtables that are not in the reference:\n\n");
    fprintf(f, "| vtable | slots | states | hits |\n|--------|-------|--------|------|\n");
    for (const auto &kv : g_obs) {
        if (strcmp(ref_name(kv.first), "-") != 0) continue;
        missing_live++;
        fprintf(f, "| `%#x` | %u | %u | %u |\n", kv.first, kv.second.slots, kv.second.state_mask,
                kv.second.hits);
    }
    fprintf(f, "\nobserved-and-unknown count: %u\n", missing_live);
    fprintf(f, "\n## tables without a reference class (first 400)\n\n"
               "| vtable | slots | unresolved | class from strings |\n"
               "|--------|-------|------------|--------------------|\n");
    int n = 0;
    for (const ClassTable &c : t) {
        if (strcmp(ref_name(c.start), "-") != 0) continue;
        if (n++ >= 400) break;
        std::map<uint32_t, std::string>::const_iterator rt = g_table_class.find(c.start);
        fprintf(f, "| `%#x` | %u | %u | %s |\n", c.start, c.slots, c.slots - c.named,
                (rt == g_table_class.end()) ? "-" : rt->second.c_str());
    }
    fclose(f);
}

}  // namespace

void live_docs_note(const Image &img, uint32_t state, int tick) {
    const char *mode = getenv("RCL_DOCS");
    if (mode && *mode == '0') return;

    uint64_t home = 0, cur = 0, mgr = 0;
    uint32_t live_state = state;
    if (!live_home(img, home, live_state, cur)) return;
    if (!home) return;
    uint64_t slot = 0;
    uint32_t so = 0, co = 0, mo = 0, ao = 0, cao = 0, cno = 0;
    live_chain(img, slot, so, co, mo, ao, cao, cno);

    g_ticks = tick;
    g_last_home = rva_of(img, home);
    g_last_cur = rva_of(img, cur);

    observe(img, home, state, tick);
    if (cur) {
        observe(img, cur, state, tick);
        rd64(img, cur + mo, mgr);
        g_last_mgr = rva_of(img, mgr);
        if (mgr) {
            uint64_t arr = 0;
            uint32_t cnt = 0;
            uint32_t cap = 0;
            rd64(img, mgr + ao, arr);
            rd32(img, mgr + cno, cnt);
            rd32(img, mgr + cao, cap);
            g_elem_cap = cap;
            if (cnt > kObjMax) cnt = kObjMax;
            g_elem_count = cnt;
            for (uint32_t i = 0; i < cnt; i++) {
                uint64_t e = 0;
                if (!rd64(img, arr + i * 8, e)) break;
                observe(img, e, state, tick);
                if (i == 0) {
                    uint64_t v = 0;
                    if (rd64(img, e, v)) g_last_elem_vt = rva_of(img, v & 0xFFFFFFFFFULL);
                }
            }
        }
    }

    const char *root = diag_root();
    mkdir_p(root);

    if ((int)state != g_last_state || (tick % 5) == 0) {
        g_last_state = (int)state;
        write_observed(img, root);
        write_missing(img, root);
    }
}

void live_docs_flush(const Image &img) {
    const char *mode = getenv("RCL_DOCS");
    if (mode && *mode == '0') return;
    const char *root = diag_root();
    mkdir_p(root);
    write_observed(img, root);
    write_missing(img, root);
}

}  // namespace rcl
