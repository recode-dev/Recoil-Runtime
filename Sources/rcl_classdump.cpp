#include "rcl_classdump.h"
#include "rcl_docdata.h"
#include "rcl_docgen.h"
#include "rcl_livedocs.h"
#include "rcl_log.h"
#include "rcl_names.h"
#include <algorithm>
#include <map>
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
const uint32_t kRunMin = 3;
const uint32_t kLooseRunMin = 4;
const uint32_t kRunMax = 512;

bool at(const Image &img, uint64_t va, void *dst, size_t n) {
    return img.read && img.read(img.ctx, va, dst, n);
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
    if ((w & 0xFF8003FFu) == 0xD10003FFu) return true;
    if ((w & 0xFC000000u) == 0x14000000u) return true;
    return false;
}

bool slot_at(const Image &img, uint64_t raw, uint64_t tlo, uint64_t thi, uint32_t *rva,
             ScanStats *st) {
    uint64_t va = raw & 0xFFFFFFFFFULL;
    uint32_t w = 0;
    if (va < tlo || va >= thi) return false;
    if (st) st->ptr_ok++;
    if (!at(img, va, &w, sizeof(w))) return false;
    if (!entry(w)) {
        if (st) {
            st->entry_rej++;
            if (!st->sample_reason) {
                st->sample_reason = 1;
                st->sample_raw = (uint32_t)(raw & 0xFFFFFFFF);
                st->sample_rva = (uint32_t)(va - img.base);
            }
        }
        return false;
    }
    if (st) st->entry_ok++;
    if (rva) *rva = (uint32_t)(va - img.base);
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


namespace {

const char *dump_root() {
    static char root[512];
    const char *env = getenv("RCL_DOCS_DIR");
    const char *rd = getenv("RCL_LOG_DIR");
    const char *home = getenv("HOME");
    if (env && *env) snprintf(root, sizeof root, "%s", env);
    else if (rd && *rd) snprintf(root, sizeof root, "%s/RecoilDump", rd);
    else if (home && *home) snprintf(root, sizeof root, "%s/Documents/RecoilDump", home);
    else snprintf(root, sizeof root, "%s", "/var/mobile/Documents/RecoilDump");
    return root;
}

struct LiveArg {
    Image img;
};

void *live_main(void *arg) {
    LiveArg *a = (LiveArg *)arg;
    int tick = 0;
    for (;;) {
        sleep(2);
        uint32_t state = 0;
        uint64_t home = 0;
        if (a->img.read && a->img.read(a->img.ctx, a->img.base + 0x1123e58, &home, 8) && home)
            a->img.read(a->img.ctx, home + 0x50, &state, 4);
        live_docs_note(a->img, state, ++tick);
    }
    return nullptr;
}

void live_boot(const Image &img) {
    static bool started = false;
    if (started) return;
    started = true;
    LiveArg *a = new LiveArg();
    a->img = img;
    pthread_t th;
    if (pthread_create(&th, nullptr, live_main, a) == 0) pthread_detach(th);
}

}  // namespace

const char *ref_name(uint32_t vt);

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

bool printable(uint32_t w) {
    for (int i = 0; i < 4; i++) {
        uint8_t c = (uint8_t)(w >> (i * 8));
        if (c < 32 || c > 126) return false;
    }
    return true;
}

std::vector<StrEnt> build_strings(const Image &img, const Layout &L) {
    std::vector<StrEnt> out;
    const uint64_t lo = L.code_lo;
    const uint64_t hi = L.code_hi;
    for (uint64_t va = lo; va + 8 <= hi; ) {
        uint32_t w = 0;
        if (!at(img, va, &w, 4)) break;
        if (!printable(w)) {
            va += 4;
            continue;
        }
        uint64_t p = va;
        uint32_t len = 0;
        while (p + 4 <= hi && len < 512) {
            uint32_t x = 0;
            if (!at(img, p, &x, 4)) break;
            if (!printable(x)) break;
            len += 4;
            p += 4;
        }
        if (len >= 8 && !(len & 3)) out.push_back({(uint32_t)(va - img.base), len});
        if (out.size() > 200000) break;
        va = p + 4;
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

void class_label(uint32_t vt, char *dst, size_t cap) {
    const char *n = ref_name(vt);
    if (n && *n && strcmp(n, "-") != 0) {
        snprintf(dst, cap, "%s", n);
        return;
    }
    snprintf(dst, cap, "vt_%06x", vt);
}

struct GlobalHit {
    uint32_t cell;
    uint32_t vt;
    uint32_t object;
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
            uint64_t r = obj - img.base;
            if (obj < img.base || r >= (img.image_vmsize ? img.image_vmsize : 0x1200000)) continue;
            if (r < L.data[i].start - img.base || r >= L.data[i].end - img.base) continue;
            uint64_t v = 0;
            if (!at(img, obj, &v, 8)) continue;
            uint32_t vt = (uint32_t)((v & 0xFFFFFFFFFULL) - img.base);
            if (vt == 0) continue;
            bool is_table = std::binary_search(tsorted.begin(), tsorted.end(), vt);
            if (!is_table) continue;
            out.push_back({(uint32_t)(va - img.base), vt, (uint32_t)r});
        }
    }
}

void write_globals(const std::vector<GlobalHit> &hits, const char *root) {
    char path[1024];
    snprintf(path, sizeof path, "%s/_globals.md", root);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# globals holding objects of a known class (singletons, managers, VTABLE holders)\n\n");
    fprintf(f, "| cell rva | object rva | class table | class | name guess |\n");
    fprintf(f, "|----------|-----------|-------------|-------|------------|\n");
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
        fprintf(f, "| `%#x` | `%#x` | `%#x` | %s | %s |\n", h.cell, h.object, h.vt, cl, g);
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
    std::vector<uint32_t> fields;
};

uint32_t adrp_imm(uint32_t w) {
    int imm = (int)(((w >> 5) & 0x7FFFFu) << 2 | ((w >> 29) & 3u));
    if (imm & 0x100000) imm -= 0x200000;
    return (uint32_t)(imm << 12);
}

void code_pass(const Image &img, const Layout &L, const std::vector<uint32_t> &starts,
               const std::vector<StrEnt> &strs, const SlotMap &slots,
               std::map<uint32_t, FnAgg> &fns) {
    for (uint64_t va = L.code_lo; va + 16 <= L.code_hi; va += 4) {
        uint32_t w0 = 0;
        if (!at(img, va, &w0, 4)) break;
        uint32_t rva = (uint32_t)(va - img.base);
        if ((w0 & 0x9F000000u) != 0x90000000u) {
            uint32_t kind = w0 & 0xFFC00000u;
            if ((kind == 0xB9400000u || kind == 0xB9000000u || kind == 0xF9400000u ||
                 kind == 0xF9000000u) &&
                ((w0 >> 5) & 31u) == 31u) {
                bool word = (kind == 0xB9400000u || kind == 0xB9000000u);
                uint32_t off = ((w0 >> 10) & 0xFFFu) << (word ? 2 : 3);
                if (off >= 8 && off < 0x1000) {
                    uint32_t fn = fn_of(starts, rva, nullptr);
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
            if (!find_str(strs, target)) continue;
            uint32_t fn = fn_of(starts, rva, nullptr);
            if (!fn || !slots.has(fn)) break;
            FnAgg &a = fns[fn];
            if (!a.first_string) a.first_string = target;
            a.strings++;
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
        const char *n = ref_name(kv.second.table);
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
        const char *n = ref_name(kv.second.table);
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
    fprintf(f, "documented classes %u | class tables %zu | table slots %zu | globals holding known "
               "objects %zu | functions with a string anchor %zu\n\n",
            kDocClassCount, tables.size(), slots.sorted.size(), gh.size(), fns.size());
    fprintf(f, "| class | table (vt) | slots | slots named by string | field candidates |\n");
    fprintf(f, "|-------|-----------|-------|----------------------|------------------|\n");
    for (size_t i = 0; i < tables.size(); i++) {
        const ClassTable &t = tables[i];
        const char *n = ref_name(t.start);
        std::string lb = (n && strcmp(n, "-") != 0) ? n : ("vt_" + std::to_string(t.start));
        uint32_t named = 0, flds = 0;
        for (const auto &kv : fns)
            if (kv.second.table == t.start) {
                if (kv.second.strings) named++;
                flds += (uint32_t)kv.second.fields.size();
            }
        fprintf(f, "| %s | `%#x` | %u | %u | %u |\n", lb.c_str(), t.start, t.slots, named, flds);
    }
    fclose(f);
}

void run_deep_scan(const Image &img, const Layout &L, const std::vector<ClassTable> &tables,
                   const char *root) {
    mkdir(root, 0755);
    const std::vector<uint32_t> starts = build_starts(img, L);
    const std::vector<StrEnt> strs = build_strings(img, L);
    SlotMap slots;
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
    code_pass(img, L, starts, strs, slots, fns);
    std::vector<GlobalHit> gh;
    scan_globals(img, L, tables, gh);
    write_strings(img, strs, fns, root);
    write_fields(fns, root);
    write_all_offsets(tables, slots, fns, gh, root);
    write_globals(gh, root);
    write_anchors_extra(tables, root);
    RCL_LOGLN("[deep] starts=%zu strings=%zu slots=%zu anchored_fns=%zu globals=%zu tables=%zu",
              starts.size(), strs.size(), slots.sorted.size(), fns.size(), gh.size(), tables.size());
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
    if (!full) {
        for (const ClassTable &c : t)
            RCL_LOGLN("  vt=0x%06x slots=%3u named=%3u seg=%s", c.start, c.slots, c.named, c.seg);
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
                  index++, c.start, c.slots, c.named, votes, c.seg, label);
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
    run_deep_scan(img, L, t, dump_root());
    RCL_LOGLN("[classes] end tables=%zu slots=%llu named_slots=%llu", t.size(),
              (unsigned long long)slots, (unsigned long long)named);
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
    if ((w & 0xFF8003FFu) == 0xD10003FFu) return true;
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

        const ClassTable *t = d.vt ? ix.table_at(d.vt) : nullptr;
        if (t) claimed.push_back(d.vt);

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
                       "|------|-----|---------|--------|\n", t->start, t->slots, t->seg);
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
        snprintf(path, sizeof path, "%s/Unknown/vt_%06x.md", root, t.start);
        FILE *f = fopen(path, "w");
        if (!f) continue;
        fprintf(f, "# vt_%06x\n\n**Class Table:** `%#x`  **Slots:** %u  **Segment:** `%s`\n\n"
                   "No documented class claims this table.\n\n| slot | rva | address | method |\n"
                   "|------|-----|---------|--------|\n", t.start, t.start, t.slots, t.seg);
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

    snprintf(path, sizeof path, "%s/_diag.md", root);
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
        fclose(dg);
    }

    RCL_LOGLN("[docs] wrote %u class files + %u table files to %s  (method addresses live: %u/%u)",
              files, unknown, root, methods_ok, methods_all);
    RCL_LOGLN("[docs] classes=%u methods=%u tables=%zu", kDocClassCount, kDocMethodCount,
              ix.tables.size());
}




namespace {

const uint64_t kHomeGlobal = 0x1123e58;
const uint64_t kCtrlGlobal = 0x1123b48;
const uint64_t kStateOff = 0x50;
const uint64_t kCurrentOff = 0x48;
const uint64_t kMgrOff = 0x28;
const uint64_t kArrOff = 0x0;
const uint64_t kCapOff = 0x8;
const uint64_t kCntOff = 0xc;
const uint32_t kObjMax = 1024;

struct Obs {
    uint32_t vt = 0;
    uint32_t state_mask = 0;
    uint32_t hits = 0;
    uint32_t slots = 0;
    int first_tick = 0;
};

std::map<uint32_t, Obs> g_obs;
std::map<uint32_t, uint32_t> g_chain;
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

void note_offset(uint32_t off, uint32_t value) {
    if (value) g_chain[off] = value;
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
    fprintf(a, "# anchors seen live (RVAs worth keeping)\n\n");
    fprintf(a, "| what | offset / global | value seen |\n|------|------------------|------------|\n");
    fprintf(a, "| home singleton | `BASE+%#llx` | `%#x` |\n", (unsigned long long)kHomeGlobal,
            g_last_home);
    fprintf(a, "| controller global | `BASE+%#llx` | `%#x` |\n", (unsigned long long)kCtrlGlobal,
            g_chain.count((uint32_t)kCtrlGlobal) ? g_chain[(uint32_t)kCtrlGlobal] : 0);
    fprintf(a, "| state | `home+%#llx` | - |\n", (unsigned long long)kStateOff);
    fprintf(a, "| current | `home+%#llx` | `%#x` |\n", (unsigned long long)kCurrentOff, g_last_cur);
    fprintf(a, "| manager | `current+%#llx` | `%#x` |\n", (unsigned long long)kMgrOff, g_last_mgr);
    fprintf(a, "| array | `manager+%#llx` | - |\n", (unsigned long long)kArrOff);
    fprintf(a, "| count | `manager+%#llx` | %u |\n", (unsigned long long)kCntOff, g_elem_count);
    fprintf(a, "| capacity | `manager+%#llx` | %u |\n", (unsigned long long)kCapOff, g_elem_cap);
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
               "| vtable | slots | unresolved |\n|--------|-------|------------|\n");
    int n = 0;
    for (const ClassTable &c : t) {
        if (strcmp(ref_name(c.start), "-") != 0) continue;
        if (n++ >= 400) break;
        fprintf(f, "| `%#x` | %u | %u |\n", c.start, c.slots, c.slots - c.named);
    }
    fclose(f);
}

}  // namespace

void live_docs_note(const Image &img, uint32_t state, int tick) {
    const char *mode = getenv("RCL_DOCS");
    if (mode && *mode == '0') return;

    uint64_t home = 0, cur = 0, mgr = 0, ctrl = 0;
    rd64(img, img.base + kHomeGlobal, home);
    rd64(img, img.base + kCtrlGlobal, ctrl);
    if (!home) return;
    rd64(img, home + kCurrentOff, cur);

    g_ticks = tick;
    note_offset((uint32_t)kCtrlGlobal, rva_of(img, ctrl));
    g_last_home = rva_of(img, home);
    g_last_cur = rva_of(img, cur);

    observe(img, home, state, tick);
    if (cur) {
        observe(img, cur, state, tick);
        rd64(img, cur + kMgrOff, mgr);
        g_last_mgr = rva_of(img, mgr);
        if (mgr) {
            uint64_t arr = 0;
            uint32_t cnt = 0;
            uint32_t cap = 0;
            rd64(img, mgr + kArrOff, arr);
            rd32(img, mgr + kCntOff, cnt);
            rd32(img, mgr + kCapOff, cap);
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

    char root[512];
    snprintf(root, sizeof root, "%s", dump_root());
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
    char root[512];
    snprintf(root, sizeof root, "%s", dump_root());
    mkdir_p(root);
    write_observed(img, root);
    write_missing(img, root);
}

}  // namespace rcl
