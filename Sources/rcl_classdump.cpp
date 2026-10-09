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
    for (int i = 0; i < L.nsegs; i++) {
        if (strncmp(segs[i].name, "__TEXT", 16) == 0) {
            L.code_lo = segs[i].start;
            L.code_hi = segs[i].end;
            continue;
        }
        if (strncmp(segs[i].name, "__LINKEDIT", 16) == 0) continue;
        if (strncmp(segs[i].name, "__PAGEZERO", 16) == 0) continue;
        if (L.data_n < 64) L.data[L.data_n++] = segs[i];
    }
    if (L.data_n == 0) {
        const uint64_t end = img.base + (img.image_vmsize ? img.image_vmsize : 0x1200000);
        Range r;
        snprintf(r.name, sizeof(r.name), "%s", "image");
        r.start = L.code_hi ? L.code_hi : img.base + 0x4000;
        r.end = end;
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
    fprintf(f, "- last home `%#x`  current `%#x`  manager `%#x`  elements %u\n", g_last_home,
            g_last_cur, g_last_mgr, g_elem_count);
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
    fprintf(a, "| element vtable | `element+0x0` | `%#x` |\n", g_last_elem_vt);
    fprintf(a, "\nlast manager field values: cap `base+%#x` count `%u`\n", 0, g_elem_count);
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
            rd64(img, mgr + kArrOff, arr);
            rd32(img, mgr + kCntOff, cnt);
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
