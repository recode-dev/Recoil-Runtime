#include "rcl_classdump.h"
#include "rcl_names.h"
#include "rcl_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>

namespace rcl {

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

bool entry(uint32_t w) {
    if (w == 0xD503233Fu || w == 0xD503237Fu || w == 0xD65F03C0u || w == 0xD503201Fu) return true;
    if ((w & 0xFFFFFF1Fu) == 0xD503241Fu) return true;
    if ((w & 0xFF800000u) == 0xA9800000u && ((w >> 5) & 31u) == 31u) return true;
    if ((w & 0xFF8003FFu) == 0xD10003FFu) return true;
    if ((w & 0xFC000000u) == 0x14000000u) return true;
    return false;
}

bool slot_at(const Image &img, uint64_t raw, uint64_t tlo, uint64_t thi, uint32_t *rva) {
    uint64_t va = raw & 0xFFFFFFFFFULL;
    uint32_t w = 0;
    if (va < tlo || va >= thi) return false;
    if (!at(img, va, &w, sizeof(w))) return false;
    if (!entry(w)) return false;
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

std::vector<ClassTable> scan_class_tables(const Image &img) {
    std::vector<ClassTable> out;
    Layout L;
    layout(img, L);
    for (int i = 0; i < L.data_n; i++) {
        uint64_t va = L.data[i].start;
        while (va + 8 <= L.data[i].end) {
            uint64_t raw = 0;
            if (!at(img, va, &raw, sizeof(raw))) break;
            if (!slot_at(img, raw, L.code_lo, L.code_hi, nullptr)) {
                va += 8;
                continue;
            }
            uint32_t n = 0;
            uint64_t p = va;
            while (p + 8 <= L.data[i].end && n < kRunMax) {
                uint64_t r2 = 0;
                if (!at(img, p, &r2, sizeof(r2))) break;
                if (!slot_at(img, r2, L.code_lo, L.code_hi, nullptr)) break;
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
                    if (!slot_at(img, r3, L.code_lo, L.code_hi, &sr)) continue;
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

void dump_class_tree(const Image &img) {
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
            if (!slot_at(img, raw, L.code_lo, L.code_hi, &sr)) continue;
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
            if (!slot_at(img, raw, L.code_lo, L.code_hi, &sr)) {
                RCL_LOGLN("    +0x%03x  ----------  -", s * 8);
                continue;
            }
            RCL_LOGLN("    +0x%03x  0x%06x  %s", s * 8, sr, name_for_rva(sr));
        }
    }
    RCL_LOGLN("[classes] end tables=%zu slots=%llu named_slots=%llu", t.size(),
              (unsigned long long)slots, (unsigned long long)named);
}

}
