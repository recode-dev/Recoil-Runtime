#include "rcl_docgen.h"
#include "rcl_classdump.h"
#include "rcl_docdata.h"
#include "rcl_log.h"
#include "rcl_names.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <vector>
#include <algorithm>

namespace rcl {

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
    const char *env = getenv("RCL_DOCS_DIR");
    const char *dir = log_dir();
    if (env && *env) snprintf(root, sizeof root, "%s", env);
    else snprintf(root, sizeof root, "%s/RecoilDump", (dir && *dir) ? dir : ".");
    mkdir_one(root);
    char path[1024];
    snprintf(path, sizeof path, "%s/Unknown", root);
    mkdir_one(path);

    DocIndex ix;
    ix.tables = scan_class_tables(img);
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

    RCL_LOGLN("[docs] wrote %u class files + %u table files to %s  (method addresses live: %u/%u)",
              files, unknown, root, methods_ok, methods_all);
    RCL_LOGLN("[docs] classes=%u methods=%u tables=%zu", kDocClassCount, kDocMethodCount,
              ix.tables.size());
}

}
