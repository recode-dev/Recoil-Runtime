#include "rcl_macho.h"
#include "rcl_log.h"

#include <algorithm>
#include <stdio.h>
#include <string.h>

namespace rcl {

namespace {

bool rd(const Image &img, uint64_t va, void *dst, size_t n) {
    return img.read && img.read(img.ctx, va, dst, n);
}

bool rd8(const Image &img, uint64_t va, uint8_t &out) { return rd(img, va, &out, 1); }

bool rd16(const Image &img, uint64_t va, uint16_t &out) { return rd(img, va, &out, 2); }
bool rd32(const Image &img, uint64_t va, uint32_t &out) { return rd(img, va, &out, 4); }
bool rd64(const Image &img, uint64_t va, uint64_t &out) { return rd(img, va, &out, 8); }

struct Cursor {
    const Image *img;
    uint64_t va;
    uint64_t left;
    bool bad;
};

bool uleb(Cursor &c, uint64_t &out) {
    out = 0;
    int shift = 0;
    for (int i = 0; i < 10; i++) {
        if (!c.left) { c.bad = true; return false; }
        uint8_t b = 0;
        if (!rd8(*c.img, c.va, b)) { c.bad = true; return false; }
        c.va += 1;
        c.left -= 1;
        out |= (uint64_t)(b & 0x7Fu) << shift;
        if (!(b & 0x80u)) return true;
        shift += 7;
    }
    c.bad = true;
    return false;
}

struct Hdr64 {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct SegCmd64 {
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

struct Sect64 {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

struct LinkEditData {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t dataoff;
    uint32_t datasize;
};

bool lc_walk(const Image &img, uint32_t &ncmds, uint64_t &first_va) {
    Hdr64 h;
    if (!rd(img, img.base, &h, sizeof h)) return false;
    if (h.magic != 0xFEEDFACFu) return false;
    ncmds = h.ncmds;
    first_va = img.base + sizeof(Hdr64);
    return true;
}

void sorted_unique(std::vector<uint32_t> &v) {
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
}

}

bool macho_insight(const Image &img, MachInsight &mi) {
    mi = MachInsight();
    Hdr64 h;
    if (!rd(img, img.base, &h, sizeof h)) return false;
    if (h.magic != 0xFEEDFACFu) return false;
    mi.ncmds = h.ncmds;
    mi.cputype = h.cputype;
    mi.cpusubtype = h.cpusubtype;
    mi.filetype = h.filetype;
    mi.flags = h.flags;
    mi.is_arm64e = ((h.cpusubtype & 0x00FFFFFFu) == 2u);

    uint64_t p = img.base + sizeof(Hdr64);
    for (uint32_t c = 0; c < h.ncmds && c < 8192; c++) {
        uint32_t cmd = 0, sz = 0;
        if (!rd32(img, p, cmd) || !rd32(img, p + 4, sz)) break;
        if (sz < 8 || sz > 0x100000u) break;

        if (cmd == kLcSegment64) {
            SegCmd64 sg;
            if (rd(img, p, &sg, sizeof sg)) {
                SegFull f;
                memcpy(f.name, sg.segname, 16);
                f.name[16] = 0;
                f.vmaddr = sg.vmaddr;
                f.vmsize = sg.vmsize;
                f.fileoff = sg.fileoff;
                f.filesize = sg.filesize;
                f.nsects = sg.nsects;
                f.maxprot = (uint32_t)sg.maxprot;
                f.initprot = (uint32_t)sg.initprot;
                mi.segs.push_back(f);
                if (f.vmsize && strncmp(f.name, "__TEXT", 16) == 0 && !mi.text_vmaddr) {
                    mi.text_vmaddr = f.vmaddr;
                    mi.text_vmsize = f.vmsize;
                }
                uint64_t sp = p + sizeof(SegCmd64);
                for (uint32_t s = 0; s < sg.nsects && s < 512; s++) {
                    Sect64 sc;
                    if (!rd(img, sp, &sc, sizeof sc)) break;
                    SecRange sr;
                    memcpy(sr.seg, sc.segname, 16);
                    sr.seg[16] = 0;
                    memcpy(sr.sect, sc.sectname, 16);
                    sr.sect[16] = 0;
                    sr.start = sc.addr;
                    sr.end = sc.addr + sc.size;
                    sr.flags = sc.flags;
                    if (sc.size) mi.sections.push_back(sr);
                    sp += sizeof(Sect64);
                }
            }
        } else if (cmd == kLcFunctionStarts) {
            LinkEditData d;
            if (rd(img, p, &d, sizeof d)) { mi.has_function_starts = d.datasize != 0; }
        } else if (cmd == kLcDataInCode) {
            LinkEditData d;
            if (rd(img, p, &d, sizeof d)) { mi.has_data_in_code = d.datasize != 0; }
        } else if (cmd == kLcSymtab) {
            uint32_t nsyms = 0;
            if (rd32(img, p + 12, nsyms) && nsyms) mi.has_symtab = true;
        } else if (cmd == kLcUuid) {
            uint8_t u[16];
            if (rd(img, p + 8, u, sizeof u)) {
                const char *hex = "0123456789abcdef";
                int w = 0;
                for (int i = 0; i < 16 && w < 36; i++) {
                    mi.uuid[w++] = hex[u[i] >> 4];
                    mi.uuid[w++] = hex[u[i] & 0xF];
                    if ((i == 3 || i == 5 || i == 7 || i == 9) && w < 36) mi.uuid[w++] = '-';
                }
                mi.uuid[w] = 0;
            }
        } else if (cmd == kLcBuildVersion) {
            rd32(img, p + 8, mi.platform);
            rd32(img, p + 12, mi.minos);
            rd32(img, p + 16, mi.sdk);
        } else if (cmd == kLcDyldChainedFixups) {
            LinkEditData d;
            if (rd(img, p, &d, sizeof d) && d.datasize) {
                mi.has_chained_fixups = true;
                uint64_t hv = 0;
                if (fileoff_to_va(mi, d.dataoff, hv)) {
                    rd32(img, hv + 16, mi.fixup_page_size);
                }
                uint64_t cv = 0;
                if (fileoff_to_va(mi, d.dataoff, cv)) {
                    uint32_t seg_count = 0;
                    if (rd32(img, cv, seg_count) && seg_count) {
                        for (uint32_t s = 0; s < seg_count && s < 256; s++) {
                            uint32_t off = 0;
                            if (!rd32(img, cv + 4 + s * 4, off)) break;
                            if (!off) continue;
                            uint64_t seg = cv + off;
                            uint16_t pf = 0, pc = 0;
                            if (!rd16(img, seg + 6, pf)) continue;
                            if (rd16(img, seg + 20, pc) && pc) mi.pointer_format = pf;
                        }
                    }
                }
            }
        } else if (cmd == kLcDyldExportsTrie) {
            LinkEditData d;
            if (rd(img, p, &d, sizeof d) && d.datasize) mi.has_exports_trie = true;
        }
        p += sz;
    }

    if (!mi.text_vmaddr && !mi.segs.empty()) {
        mi.text_vmaddr = mi.segs[0].vmaddr;
        mi.text_vmsize = mi.segs[0].vmsize;
    }
    mi.slide = img.base >= mi.text_vmaddr ? img.base - mi.text_vmaddr : 0;
    mi.text_lo = mi.text_vmaddr + mi.slide;
    mi.text_hi = mi.text_lo + mi.text_vmsize;
    for (size_t i = 0; i < mi.segs.size(); i++) {
        uint64_t lo = mi.segs[i].vmaddr + mi.slide;
        uint64_t hi = lo + mi.segs[i].vmsize;
        if (!mi.image_lo || lo < mi.image_lo) mi.image_lo = lo;
        if (hi > mi.image_hi) mi.image_hi = hi;
        if (strncmp(mi.segs[i].name, "__TEXT", 16) == 0) {
            if (!mi.has_unwind_info) {
                for (size_t k = 0; k < mi.sections.size(); k++)
                    if (strncmp(mi.sections[k].sect, "__unwind_info", 16) == 0)
                        mi.has_unwind_info = true;
            }
        }
    }
    if (!mi.has_unwind_info) {
        uint64_t lo = 0, hi = 0;
        if (section_range(mi, "__unwind_info", "__TEXT", lo, hi)) mi.has_unwind_info = true;
    }
    mi.ok = mi.text_vmsize != 0;
    return mi.ok;
}

bool va_inside_image(const MachInsight &mi, uint64_t va) {
    for (size_t i = 0; i < mi.segs.size(); i++) {
        if (!mi.segs[i].vmsize) continue;
        uint64_t lo = mi.segs[i].vmaddr + mi.slide;
        uint64_t hi = lo + mi.segs[i].vmsize;
        if (va >= lo && va < hi) return true;
    }
    return false;
}

bool fileoff_to_va(const MachInsight &mi, uint64_t fileoff, uint64_t &va) {
    for (size_t i = 0; i < mi.segs.size(); i++) {
        const SegFull &s = mi.segs[i];
        if (!s.filesize) continue;
        if (fileoff >= s.fileoff && fileoff < s.fileoff + s.filesize) {
            va = s.vmaddr + mi.slide + (fileoff - s.fileoff);
            return true;
        }
    }
    return false;
}

bool section_range(const MachInsight &mi, const char *sect, const char *seg, uint64_t &lo, uint64_t &hi) {
    for (size_t i = 0; i < mi.sections.size(); i++) {
        const SecRange &s = mi.sections[i];
        if (sect && strncmp(s.sect, sect, 16) != 0) continue;
        if (seg && strncmp(s.seg, seg, 16) != 0) continue;
        lo = s.start + mi.slide;
        hi = s.end + mi.slide;
        return hi > lo;
    }
    return false;
}

void sections_named(const MachInsight &mi, const char *sect, std::vector<SecRange> &out) {
    for (size_t i = 0; i < mi.sections.size(); i++) {
        if (strncmp(mi.sections[i].sect, sect, 16) != 0) continue;
        SecRange s = mi.sections[i];
        s.start += mi.slide;
        s.end += mi.slide;
        out.push_back(s);
    }
}

uint64_t macho_slot_value(const Image &img, const MachInsight &mi, uint64_t raw, int *how) {
    if (how) *how = 0;
    if (!raw) return 0;
    uint64_t v = raw;
    if (mi.is_arm64e) {
        uint64_t stripped = v & 0x0000FFFFFFFFFFFFULL;
        if (stripped && va_inside_image(mi, stripped)) {
            if (how) *how = 1;
            return stripped;
        }
    }
    if (va_inside_image(mi, v)) {
        if (how) *how = 2;
        return v;
    }
    uint64_t t36 = v & 0xFFFFFFFFFULL;
    if (t36) {
        if (mi.slide && va_inside_image(mi, t36 + mi.slide)) {
            if (how) *how = 3;
            return t36 + mi.slide;
        }
        if (va_inside_image(mi, mi.slide + t36)) {
            if (how) *how = 4;
            return mi.slide + t36;
        }
        if (img.base && va_inside_image(mi, img.base + t36)) {
            if (how) *how = 5;
            return img.base + t36;
        }
    }
    return 0;
}

std::vector<uint32_t> read_function_starts(const Image &img, const MachInsight &mi) {
    std::vector<uint32_t> out;
    if (!mi.has_function_starts || !mi.text_vmsize) return out;

    uint32_t ncmds = 0;
    uint64_t p = 0;
    if (!lc_walk(img, ncmds, p)) return out;
    for (uint32_t c = 0; c < ncmds && c < 8192; c++) {
        uint32_t cmd = 0, sz = 0;
        if (!rd32(img, p, cmd) || !rd32(img, p + 4, sz)) break;
        if (sz < 8 || sz > 0x100000u) break;
        if (cmd == kLcFunctionStarts) {
            LinkEditData d;
            if (!rd(img, p, &d, sizeof d)) break;
            uint64_t base_va = 0;
            if (!fileoff_to_va(mi, d.dataoff, base_va)) break;
            Cursor cur{&img, base_va, d.datasize, false};
            uint64_t addr = 0;
            uint32_t accepted = 0, total = 0;
            while (cur.left && !cur.bad) {
                uint64_t delta = 0;
                if (!uleb(cur, delta)) break;
                if (!delta) break;
                addr += delta;
                total++;
                uint64_t va = addr;
                if (va >= mi.text_lo && va < mi.text_hi) {
                    out.push_back((uint32_t)(va - img.base));
                    accepted++;
                }
            }
            if (total && accepted * 100 >= total * 95) {
                sorted_unique(out);
                return out;
            }
            out.clear();
            Cursor cur2{&img, base_va, d.datasize, false};
            addr = mi.text_vmaddr;
            accepted = 0;
            total = 0;
            while (cur2.left && !cur2.bad) {
                uint64_t delta = 0;
                if (!uleb(cur2, delta)) break;
                if (!delta) break;
                addr += delta;
                total++;
                uint64_t va = addr + mi.slide;
                if (va >= mi.text_lo && va < mi.text_hi) {
                    out.push_back((uint32_t)(va - img.base));
                    accepted++;
                }
            }
            if (total && accepted * 100 >= total * 95) {
                sorted_unique(out);
                return out;
            }
            out.clear();
            break;
        }
        p += sz;
    }
    return out;
}

std::vector<SecRange> read_data_in_code(const Image &img, const MachInsight &mi) {
    std::vector<SecRange> out;
    if (!mi.has_data_in_code) return out;
    uint32_t ncmds = 0;
    uint64_t p = 0;
    if (!lc_walk(img, ncmds, p)) return out;
    for (uint32_t c = 0; c < ncmds && c < 8192; c++) {
        uint32_t cmd = 0, sz = 0;
        if (!rd32(img, p, cmd) || !rd32(img, p + 4, sz)) break;
        if (sz < 8 || sz > 0x100000u) break;
        if (cmd == kLcDataInCode) {
            LinkEditData d;
            if (!rd(img, p, &d, sizeof d)) break;
            uint64_t base_va = 0;
            if (!fileoff_to_va(mi, d.dataoff, base_va)) break;
            uint32_t n = d.datasize / 8;
            for (uint32_t i = 0; i < n && i < 65536; i++) {
                uint32_t off = 0;
                uint16_t len16 = 0, kind = 0;
                if (!rd32(img, base_va + i * 8, off)) break;
                if (!rd16(img, base_va + i * 8 + 4, len16)) break;
                if (!rd16(img, base_va + i * 8 + 6, kind)) break;
                const uint32_t len = len16;
                if (kind != 1 && kind != 2) continue;
                SecRange r;
                snprintf(r.seg, sizeof r.seg, "%s", "__TEXT");
                snprintf(r.sect, sizeof r.sect, "%s", kind == 1 ? "data" : "jump_table");
                r.start = mi.text_vmaddr + mi.slide + off;
                r.end = r.start + len;
                r.flags = 0;
                out.push_back(r);
            }
            break;
        }
        p += sz;
    }
    return out;
}

std::vector<uint32_t> read_unwind_starts(const Image &img, const MachInsight &mi) {
    std::vector<uint32_t> out;
    uint64_t lo = 0, hi = 0;
    if (!section_range(mi, "__unwind_info", "__TEXT", lo, hi)) return out;
    if (hi - lo < 32) return out;

    uint32_t version = 0, index_count = 0, index_off = 0;
    if (!rd32(img, lo, version)) return out;
    if ((version >> 24) != 1) return out;
    if (!rd32(img, lo + 20, index_count)) return out;
    if (!rd32(img, lo + 24, index_off)) return out;
    if (!index_count || index_count > 65536) return out;
    if (!index_off || lo + index_off >= hi) return out;

    uint32_t accepted = 0, total = 0;
    for (uint32_t i = 0; i < index_count; i++) {
        uint64_t ient = lo + index_off + (uint64_t)i * 12;
        uint32_t func_off = 0, page_off = 0;
        if (!rd32(img, ient, func_off)) break;
        if (!rd32(img, ient + 4, page_off)) break;
        if (!page_off) continue;
        uint64_t page_base = lo + page_off;
        if (page_base + 2 > hi) continue;

        uint16_t first = 0;
        if (!rd16(img, page_base, first)) continue;

        if (first & 1u) {
            total++;
            uint64_t va = mi.text_vmaddr + mi.slide + (uint64_t)func_off;
            if (va >= mi.text_lo && va < mi.text_hi) {
                out.push_back((uint32_t)(va - img.base));
                accepted++;
            }
            continue;
        }

        uint64_t sh = page_base + (uint64_t)first;
        uint32_t kind = 0;
        uint16_t entry_page_off = 0, entry_count = 0;
        if (!rd32(img, sh, kind)) continue;
        if (!rd16(img, sh + 4, entry_page_off)) continue;
        if (!rd16(img, sh + 6, entry_count)) continue;
        if (!entry_count || entry_count > 8192) continue;

        uint64_t entries = sh + (uint64_t)entry_page_off;
        if (kind == 2) {
            for (uint32_t e = 0; e < entry_count; e++) {
                uint32_t foff = 0;
                if (!rd32(img, entries + (uint64_t)e * 8, foff)) break;
                total++;
                uint64_t va = mi.text_vmaddr + mi.slide + foff;
                if (va >= mi.text_lo && va < mi.text_hi) {
                    out.push_back((uint32_t)(va - img.base));
                    accepted++;
                }
            }
        } else if (kind == 3) {
            Cursor cur{&img, entries, (uint64_t)entry_count * 4u + 64u, false};
            uint64_t addr = mi.text_vmaddr + (uint64_t)func_off;
            for (uint32_t e = 0; e < entry_count; e++) {
                uint64_t delta = 0, enc = 0;
                if (!uleb(cur, delta)) break;
                if (!uleb(cur, enc)) break;
                if (e) addr += delta;
                total++;
                uint64_t va = addr + mi.slide;
                if (va >= mi.text_lo && va < mi.text_hi) {
                    out.push_back((uint32_t)(va - img.base));
                    accepted++;
                }
            }
        }
    }
    if (!total) return out;
    if (accepted * 100 < total * 90) {
        out.clear();
        return out;
    }
    sorted_unique(out);
    return out;
}

std::string build_version_text(const MachInsight &mi) {
    const char *plat = "?";
    switch (mi.platform) {
        case 1: plat = "macOS"; break;
        case 2: plat = "iOS"; break;
        case 3: plat = "tvOS"; break;
        case 4: plat = "watchOS"; break;
        case 5: plat = "bridgeOS"; break;
        case 6: plat = "macCatalyst"; break;
        case 7: plat = "iOSSimulator"; break;
        case 8: plat = "tvOSSimulator"; break;
        case 9: plat = "watchOSSimulator"; break;
        case 10: plat = "driverKit"; break;
        case 11: plat = "visionOS"; break;
        default: break;
    }
    char buf[96];
    snprintf(buf, sizeof buf, "%s %u.%u.%u sdk %u.%u", plat, (mi.minos >> 16) & 0xFFFFu,
             (mi.minos >> 8) & 0xFFu, mi.minos & 0xFFu, (mi.sdk >> 16) & 0xFFFFu,
             (mi.sdk >> 8) & 0xFFu);
    return std::string(buf);
}

bool entry_prologue(uint32_t w) {
    if (w == 0xD503233Fu || w == 0xD503237Fu || w == 0xD65F03C0u || w == 0xD503201Fu) return true;
    if (w == 0xD503245Fu) return true;
    if ((w & 0xFF800000u) == 0xA9800000u && ((w >> 5) & 31u) == 31u) return true;
    if ((w & 0xFF800000u) == 0xA9000000u && ((w >> 5) & 31u) == 31u) return true;
    if ((w & 0xFFC003FFu) == 0xD10003FFu) return true;
    if ((w & 0xFF8003FFu) == 0xD10003FFu) return true;
    if ((w & 0xFFFFFFE0u) == 0x910003E0u) return true;
    if ((w & 0xFFFFFC1Fu) == 0xD4200000u) return true;
    if ((w & 0xFC000000u) == 0x14000000u) return true;
    if ((w & 0xFFE00C00u) == 0xF8000C00u && ((w >> 5) & 31u) == 31u) return true;
    if ((w & 0xFFE00C00u) == 0xB8000C00u && ((w >> 5) & 31u) == 31u) return true;
    if ((w & 0xFFC00000u) == 0x90000000u || (w & 0xFFC00000u) == 0x10000000u) return true;
    return false;
}

bool leaf_getter_at(const Image &img, uint32_t rva) {
    uint32_t a = 0, b = 0, c = 0;
    if (!rd32(img, img.base + rva, a)) return false;
    const uint32_t op = a & 0xFFC00000u;
    if (op != 0xB9400000u && op != 0xF9400000u && op != 0x39400000u && op != 0x79400000u)
        return false;
    if ((a & 0x1Fu) != 0u) return false;
    if (((a >> 5) & 0x1Fu) != 0u) return false;
    if (!rd32(img, img.base + rva + 4, b)) return false;
    if (b == 0xD65F03C0u) return true;
    const uint32_t sh = b & 0x7F800000u;
    if (sh == 0x53000000u || sh == 0x13000000u) {
        if (!rd32(img, img.base + rva + 8, c)) return false;
        return c == 0xD65F03C0u;
    }
    return false;
}

bool in_ranges(const std::vector<SecRange> &r, uint64_t va) {
    for (size_t i = 0; i < r.size(); i++)
        if (va >= r[i].start && va < r[i].end) return true;
    return false;
}

bool FnStarts::is_start(uint32_t rva) const {
    return std::binary_search(v.begin(), v.end(), rva);
}

uint32_t FnStarts::fn_at(uint32_t rva, bool *at_start) const {
    uint32_t lo = 0, hi = (uint32_t)v.size();
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        if (v[mid] <= rva) lo = mid + 1;
        else hi = mid;
    }
    if (!lo) {
        if (at_start) *at_start = false;
        return 0;
    }
    if (at_start) *at_start = (v[lo - 1] == rva);
    return v[lo - 1];
}

uint32_t FnStarts::end_of(uint32_t rva) const {
    uint32_t idx = 0, lo = 0, hi = (uint32_t)v.size();
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        if (v[mid] <= rva) lo = mid + 1;
        else hi = mid;
    }
    if (!lo) return 0;
    idx = lo - 1;
    if (idx + 1 < v.size()) return v[idx + 1];
    return 0;
}

uint32_t FnStarts::size_of(uint32_t rva) const {
    uint32_t e = end_of(rva);
    if (!e || e <= rva) return 0;
    return e - rva;
}

void fn_starts_build(const Image &img, const MachInsight &mi, FnStarts &fs) {
    fs = FnStarts();
    if (!mi.text_vmsize) return;

    fs.v = read_function_starts(img, mi);
    if (fs.v.size() >= 128) {
        fs.exact = true;
        fs.from_function_starts = true;
        fs.scanned_ok = (uint32_t)fs.v.size();
        return;
    }
    fs.v.clear();

    fs.v = read_unwind_starts(img, mi);
    if (fs.v.size() >= 128) {
        fs.exact = true;
        fs.from_unwind = true;
        fs.scanned_ok = (uint32_t)fs.v.size();
        return;
    }
    fs.v.clear();

    uint32_t prev = 0;
    uint32_t accepted = 0, rejected = 0;
    for (uint64_t va = mi.text_lo; va + 4 <= mi.text_hi; va += 4) {
        uint32_t w = 0;
        if (!rd32(img, va, w)) break;
        const bool boundary = (prev == 0xD65F03C0u) || ((prev & 0xFC000000u) == 0x14000000u) ||
                              (prev == 0xD503201Fu);
        if (boundary || va == mi.text_lo) {
            const uint32_t rva = (uint32_t)(va - img.base);
            if (entry_prologue(w) || leaf_getter_at(img, rva)) {
                fs.v.push_back(rva);
                accepted++;
            } else {
                rejected++;
            }
        }
        prev = w;
    }
    sorted_unique(fs.v);
    fs.from_scan = true;
    fs.scanned_ok = accepted;
    fs.rejected = rejected;
}

}
