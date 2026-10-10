#include "rcl_scan.h"
#include "rcl_log.h"
#include <algorithm>
#include <map>
#include <stdlib.h>
#include <string.h>

namespace rcl
{

static bool rd_raw(const Image &img, uint64_t va, void *dst, size_t n)
{
    return img.read && img.read(img.ctx, va, dst, n);
}

bool macho_text_range(const Image &img, uint64_t &lo, uint64_t &hi)
{
    lo = 0;
    hi = 0;
    uint8_t hdr[32];
    if (!rd_raw(img, img.base, hdr, sizeof hdr))
        return false;
    const uint32_t ncmds = *(const uint32_t *)(hdr + 16);
    uint64_t cursor = img.base + 32;
    for (uint32_t c = 0; c < ncmds && c < 4096; c++)
    {
        uint8_t lc[8];
        if (!rd_raw(img, cursor, lc, sizeof lc))
            return false;
        const uint32_t cmd = *(const uint32_t *)lc;
        const uint32_t sz = *(const uint32_t *)(lc + 4);
        if (sz < 8)
            return false;
        if (cmd == 0x19)
        {
            uint8_t sg[72];
            if (rd_raw(img, cursor, sg, sizeof sg))
            {
                const char *nm = (const char *)(sg + 8);
                const uint64_t vmaddr = *(const uint64_t *)(sg + 24);
                const uint64_t vmsize = *(const uint64_t *)(sg + 32);
                if (vmsize && strncmp(nm, "__TEXT", 16) == 0)
                {
                    const uint64_t slide = img.base >= vmaddr ? img.base - vmaddr : 0;
                    lo = vmaddr + slide;
                    hi = vmaddr + vmsize + slide;
                    return hi > lo;
                }
            }
        }
        cursor += sz;
    }
    return false;
}

bool macho_data_ranges(const Image &img, uint64_t *lo, uint64_t *hi, int cap, int &count)
{
    count = 0;
    uint8_t hdr[32];
    if (!rd_raw(img, img.base, hdr, sizeof hdr))
        return false;
    const uint32_t ncmds = *(const uint32_t *)(hdr + 16);
    uint64_t cursor = img.base + 32;
    uint64_t text_vmaddr = 0;
    for (uint32_t c = 0; c < ncmds && c < 4096; c++)
    {
        uint8_t lc[8];
        if (!rd_raw(img, cursor, lc, sizeof lc))
            break;
        const uint32_t cmd = *(const uint32_t *)lc;
        const uint32_t sz = *(const uint32_t *)(lc + 4);
        if (sz < 8)
            break;
        if (cmd == 0x19)
        {
            uint8_t sg[72];
            if (rd_raw(img, cursor, sg, sizeof sg))
            {
                const char *nm = (const char *)(sg + 8);
                const uint64_t vmaddr = *(const uint64_t *)(sg + 24);
                const uint64_t vmsize = *(const uint64_t *)(sg + 32);
                if (vmsize)
                {
                    if (strncmp(nm, "__TEXT", 16) == 0)
                        text_vmaddr = vmaddr;
                    else if (strncmp(nm, "__LINKEDIT", 16) != 0 &&
                             strncmp(nm, "__PAGEZERO", 16) != 0 && count < cap)
                    {
                        lo[count] = vmaddr;
                        hi[count] = vmaddr + vmsize;
                        count++;
                    }
                }
            }
        }
        cursor += sz;
    }
    const uint64_t slide = img.base >= text_vmaddr ? img.base - text_vmaddr : 0;
    for (int i = 0; i < count; i++)
    {
        lo[i] += slide;
        hi[i] += slide;
    }
    return count > 0;
}

uint64_t macho_image_size(const void *macho_header)
{
    const uint8_t *h = (const uint8_t *)macho_header;
    if (!h)
        return 0;
    const uint32_t ncmds = *(const uint32_t *)(h + 16);
    const uint8_t *p = h + 32;
    uint64_t lo = 0, hi = 0;
    for (uint32_t c = 0; c < ncmds; c++)
    {
        const uint32_t cmd = *(const uint32_t *)p;
        const uint32_t sz = *(const uint32_t *)(p + 4);
        if (sz < 8)
            break;
        if (cmd == 0x19)
        {
            const uint64_t vm = *(const uint64_t *)(p + 24);
            const uint64_t vs = *(const uint64_t *)(p + 32);
            if (vm && vs)
            {
                if (!lo || vm < lo)
                    lo = vm;
                if (vm + vs > hi)
                    hi = vm + vs;
            }
        }
        p += sz;
    }
    return hi > lo ? hi - lo : 0;
}

bool Image::cstr(uint64_t va, std::string &out) const
{
    out.clear();
    for (int i = 0; i < 48; i++)
    {
        char c = 0;
        if (!read(ctx, va + i, &c, 1))
            return false;
        if (c == 0)
            break;
        if ((unsigned char)c < 32 || (unsigned char)c > 126)
            return false;
        out.push_back(c);
    }
    return out.size() >= 3;
}

static inline int64_t sign_extend(uint64_t v, int bits)
{
    uint64_t m = 1ULL << (bits - 1);
    return (int64_t)((v ^ m) - m);
}

bool branch_target(const Image &img, uint64_t va, uint64_t &target)
{
    uint32_t w = 0;
    if (!img.u32(va, w))
        return false;
    if ((w & 0xFC000000) == 0x14000000)
    {
        target = va + ((uint64_t)(sign_extend(w & 0x03FFFFFF, 26)) << 2);
        return true;
    }
    if ((w & 0xFF000010) == 0x54000000)
    {
        target = va + ((uint64_t)(sign_extend((w >> 5) & 0x7FFFF, 19)) << 2);
        return true;
    }
    if ((w & 0x7E000000) == 0x34000000)
    {
        target = va + ((uint64_t)(sign_extend((w >> 5) & 0x7FFFF, 19)) << 2);
        return true;
    }
    return false;
}

static bool is_bl_to(const Image &img, uint64_t va, uint64_t target)
{
    uint32_t w = 0;
    if (!img.u32(va, w))
        return false;
    if ((w & 0xFC000000) != 0x94000000)
        return false;
    uint64_t t = va + ((uint64_t)(sign_extend(w & 0x03FFFFFF, 26)) << 2);
    return t == target;
}

static bool movz_w1(uint32_t w, uint32_t &imm)
{
    if ((w & 0xFFE00000) != 0x52800000)
        return false;
    if ((w & 0x1F) != 1)
        return false;
    imm = (w >> 5) & 0xFFFF;
    return true;
}

static bool adrp_at(const Image &img, uint64_t va, uint64_t &page, uint32_t &rd)
{
    uint32_t w = 0;
    if (!img.u32(va, w))
        return false;
    if ((w & 0x9F000000) != 0x90000000)
        return false;
    uint64_t imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3);
    page = (va & ~0xFFFULL) + ((uint64_t)sign_extend(imm, 21) << 12);
    rd = w & 0x1F;
    return true;
}

static bool add_imm(const Image &img, uint64_t va, uint32_t rd, uint64_t &res)
{
    uint32_t w = 0;
    if (!img.u32(va, w))
        return false;
    if ((w & 0x7F000000) != 0x11000000)
        return false;
    if (((w >> 5) & 0x1F) != rd)
        return false;
    uint64_t page = 0;
    if (!adrp_at(img, va - 4, page, rd))
        return false;
    res = page + ((w >> 10) & 0xFFF);
    return true;
}

static int dest_reg(uint32_t w)
{

    if ((w & 0x7F800000) == 0x52800000 || (w & 0x7F800000) == 0x12800000)
        return w & 0x1F;

    if ((w & 0x3B000000) == 0x39000000 && ((w >> 22) & 1))
        return w & 0x1F;
    uint32_t ldu = w & 0xFFE00C00;
    if (ldu == 0x38400000)
        return w & 0x1F;
    if (ldu == 0xB8400000)
        return w & 0x1F;
    if (ldu == 0xF8400000)
        return w & 0x1F;
    uint32_t ldp = w & 0x7FC00000;
    if (ldp == 0x29400000 || ldp == 0xA9400000 || ldp == 0x69400000 || ldp == 0x28C00000)
        return w & 0x1F;

    if ((w & 0x1F000000) == 0x11000000 && (w & 0x0F000000) != 0x0F000000)
        return w & 0x1F;
    if ((w & 0x1F200000) == 0x0B000000)
        return w & 0x1F;

    if ((w & 0x1F200000) == 0x0A000000)
        return w & 0x1F;
    if ((w & 0x1F800000) == 0x12000000)
        return w & 0x1F;

    if ((w & 0x1FE00000) == 0x1A800000)
        return w & 0x1F;

    if ((w & 0xFFE0FFE0) == 0x2A0003E0 || (w & 0xFFE0FFE0) == 0xAA0003E0)
        return w & 0x1F;

    if ((w & 0x9F000000) == 0x90000000 || (w & 0x9F000000) == 0x10000000)
        return w & 0x1F;
    return -1;
}

StoreDecoded decode_store_to_w0(const Image &img, uint64_t at, int n)
{
    StoreDecoded d;
    for (int k = 0; k < n; k++)
    {
        uint32_t w = 0;
        if (!img.u32(at + 4 * k, w))
            break;
        if ((w & 0xFFC0001F) == 0x39000000)
        {
            d = {true, "strb", (int64_t)((w >> 10) & 0xFFF), 1};
            return d;
        }
        if ((w & 0xFFC0001F) == 0xB9000000)
        {
            d = {true, "str", (int64_t)(((w >> 10) & 0xFFF) * 4), 4};
            return d;
        }
        if ((w & 0xFFC0001F) == 0xF9000000)
        {
            d = {true, "strx", (int64_t)(((w >> 10) & 0xFFF) * 8), 8};
            return d;
        }
        if ((w & 0xFFE00C1F) == 0x38000000)
        {
            d = {true, "sturb", sign_extend((w >> 12) & 0x1FF, 9), 1};
            return d;
        }
        if ((w & 0xFFE00C1F) == 0xB8000000)
        {
            d = {true, "stur", sign_extend((w >> 12) & 0x1FF, 9), 4};
            return d;
        }
        if ((w & 0xFFC00000) == 0x39000000 && (w & 0x1F) == 31)
        {
            d = {true, "strb_zr", (int64_t)((w >> 10) & 0xFFF), 1};
            return d;
        }
        if ((w & 0xFFC00000) == 0x29000000)
        {
            d = {true, "stp_w", (int64_t)(((w >> 15) & 0x7F) * 4), 8};
            return d;
        }
    }
    return d;
}

static void anchor_scores(const Image &img, const Seeds &s, std::map<uint64_t, uint32_t> &prop,
                          std::map<uint64_t, uint32_t> &col, std::map<uint64_t, uint32_t> &bat)
{
    const uint64_t lo = img.base + s.text_off;
    const uint64_t hi = img.base + s.text_end_off;
    if (hi <= lo)
        return;
    for (uint64_t va = lo; va + 4 <= hi; va += 4)
    {
        uint32_t w = 0;
        if (!img.u32(va, w))
            continue;
        if ((w & 0xFC000000) != 0x94000000)
            continue;
        const uint64_t t = va + ((uint64_t)(sign_extend(w & 0x03FFFFFF, 26)) << 2);
        if (t < lo || t >= hi)
            continue;

        bool id_ok = false;
        for (int k = 1; k <= 4; k++)
        {
            uint32_t p = 0;
            if (!img.u32(va - 4 * k, p))
                break;
            uint32_t imm = 0;
            if (movz_w1(p, imm))
            {
                id_ok = true;
                break;
            }
        }
        StoreDecoded d = decode_store_to_w0(img, va + 4, 8);
        const bool store_ok = d.found && d.off >= 0 && d.off < 0x100000;
        if (id_ok && store_ok)
            prop[t]++;

        bool str_ok = false;
        for (int k = 1; k <= 4; k++)
        {
            uint64_t page = 0;
            uint32_t rd = 0;
            if (!adrp_at(img, va - 4 * k, page, rd))
                continue;
            uint64_t full = 0;
            if (!add_imm(img, va - 4 * k + 4, rd, full))
                continue;
            std::string nm;
            if (img.cstr(full, nm))
            {
                str_ok = true;
                break;
            }
        }
        if (str_ok && store_ok)
            col[t]++;

        for (int k = 1; k <= 6; k++)
        {
            uint32_t p = 0;
            if (!img.u32(va + 4 * k, p))
                break;
            if ((p & 0xFFC00000) == 0xF9400000 && ((p >> 5) & 0x1F) == 0 &&
                ((p >> 10) & 0xFFF) * 8 == 0x28)
            {
                bat[t]++;
                break;
            }
        }
    }
}

static std::vector<AnchorHit> rank_hits(const std::map<uint64_t, uint32_t> &m)
{
    std::vector<AnchorHit> v;
    v.reserve(m.size());
    for (std::map<uint64_t, uint32_t>::const_iterator it = m.begin(); it != m.end(); ++it)
        v.push_back({it->first, it->second});
    std::sort(v.begin(), v.end(),
              [](const AnchorHit &a, const AnchorHit &b) { return a.score > b.score; });
    return v;
}

static void log_hits(const char *tag, const std::vector<AnchorHit> &v, uint64_t base)
{
    RCL_LOGLN("[anchor] %s:", tag);
    if (v.empty())
    {
        RCL_LOGLN("   (no candidate)");
        return;
    }
    for (size_t i = 0; i < v.size() && i < 6; i++)
        RCL_LOGLN("   score=%-4u rva=0x%06x", v[i].score, (unsigned)(v[i].addr - base));
}

static uint64_t env_rva(const char *name)
{
    const char *v = getenv(name);
    if (!v || !*v)
        return 0;
    return strtoull(v, nullptr, 0);
}

Seeds Seeds::discover(const Image &img)
{
    Seeds s;
    uint64_t lo = 0, hi = 0;
    if (!macho_text_range(img, lo, hi))
    {
        lo = img.base;
        hi = img.base + (img.image_vmsize ? img.image_vmsize : img.vmsize);
    }
    s.text_off = lo > img.base ? lo - img.base : 0;
    s.text_end_off = hi > img.base ? hi - img.base : (img.vmsize ? img.vmsize : 0);
    if (s.text_end_off <= s.text_off)
        return s;

    std::map<uint64_t, uint32_t> prop, col, bat;
    anchor_scores(img, s, prop, col, bat);

    const std::vector<AnchorHit> pr = rank_hits(prop);
    const std::vector<AnchorHit> cr = rank_hits(col);
    const std::vector<AnchorHit> br = rank_hits(bat);
    log_hits("getProperty", pr, img.base);
    log_hits("getColumnName", cr, img.base);
    log_hits("getBattle", br, img.base);

    const uint32_t kMinAnchorScore = 2;
    const uint64_t ov_p = env_rva("RCL_PROPGET_RVA");
    const uint64_t ov_c = env_rva("RCL_COLNAME_RVA");
    const uint64_t ov_b = env_rva("RCL_GETBATTLE_RVA");

    if (ov_p)
    {
        s.propget_off = ov_p;
    }
    else if (!pr.empty() && pr[0].score >= kMinAnchorScore)
    {
        s.propget_off = pr[0].addr - img.base;
        s.propget_score = pr[0].score;
    }
    if (ov_c)
    {
        s.colname_off = ov_c;
    }
    else if (!cr.empty() && cr[0].score >= kMinAnchorScore)
    {
        s.colname_off = cr[0].addr - img.base;
        s.colname_score = cr[0].score;
    }
    if (ov_b)
    {
        s.getbattle_off = ov_b;
    }
    else if (!br.empty() && br[0].score >= kMinAnchorScore)
    {
        s.getbattle_off = br[0].addr - img.base;
        s.getbattle_score = br[0].score;
    }

    s.auto_found = true;
    RCL_LOGLN("[anchor] selected getbattle=0x%06llx(%u) propget=0x%06llx(%u) colname=0x%06llx(%u) "
              "text=0x%llx..0x%llx",
              (unsigned long long)s.getbattle_off, s.getbattle_score,
              (unsigned long long)s.propget_off, s.propget_score, (unsigned long long)s.colname_off,
              s.colname_score, (unsigned long long)s.text_off, (unsigned long long)s.text_end_off);
    return s;
}

std::vector<PropSite> scan_property_sites(const Image &img, const Seeds &s)
{
    std::vector<PropSite> out;
    if (!s.propget_off)
        return out;
    const uint64_t target = img.base + s.propget_off;
    for (uint64_t va = img.base + s.text_off; va + 4 <= img.base + s.text_end_off; va += 4)
    {
        if (!is_bl_to(img, va, target))
            continue;
        PropSite p{};
        p.site = va;
        p.id = 0;
        for (int k = 1; k <= 4; k++)
        {
            uint32_t w = 0;
            if (!img.u32(va - 4 * k, w))
                break;
            uint32_t imm = 0;
            if (movz_w1(w, imm))
            {
                p.id = imm;
                break;
            }
        }
        StoreDecoded d = decode_store_to_w0(img, va + 4, 8);
        if (d.found && d.off >= 0 && d.off < 0x100000)
        {
            p.field = (uint32_t)d.off;
            p.width = d.width;
            p.kind = d.kind;
            out.push_back(p);
        }
    }
    return out;
}

std::vector<ColumnSite> scan_column_sites(const Image &img, const Seeds &s)
{
    std::vector<ColumnSite> out;
    if (!s.colname_off)
        return out;
    const uint64_t target = img.base + s.colname_off;
    for (uint64_t va = img.base + s.text_off; va + 4 <= img.base + s.text_end_off; va += 4)
    {
        if (!is_bl_to(img, va, target))
            continue;
        std::string name;
        for (int k = 1; k <= 4; k++)
        {
            uint64_t strva = 0;
            uint32_t rd = 0;
            if (!adrp_at(img, va - 4 * k, strva, rd))
                continue;
            uint64_t full = 0;
            if (!add_imm(img, va - 4 * k + 4, rd, full))
                continue;
            (void)strva;
            if (img.cstr(full, name))
                break;
            name.clear();
        }
        if (name.empty())
            continue;

        for (int k = 1; k <= 8; k++)
        {
            uint32_t w = 0;
            if (!img.u32(va + 4 * k, w))
                break;
            bool isStr = ((w & 0xFFC00000) == 0xB9000000 && (w & 0x1F) == 0);
            bool isStur = ((w & 0xFFE00C00) == 0xB8000000 && (w & 0x1F) == 0);
            if (!isStr && !isStur)
                continue;
            uint32_t imm =
                isStr ? ((w >> 10) & 0xFFF) : (uint32_t)sign_extend((w >> 12) & 0x1FF, 9);
            uint32_t base = (w >> 5) & 0x1F;
            uint64_t slot_va = 0;
            for (int b = 1; b <= 8; b++)
            {
                uint64_t page = 0;
                uint32_t rd = 0;
                if (!adrp_at(img, va + 4 * k - 4 * b, page, rd))
                    continue;
                if (rd == base)
                {
                    slot_va = page + (uint64_t)imm * 4;
                    break;
                }
            }
            out.push_back({name, imm, va, slot_va});
            break;
        }
    }
    return out;
}

std::vector<ClassColumns> scan_class_columns(const Image &img, const Seeds &s,
                                             const std::vector<ClassBoundary> &boundaries)
{
    std::vector<ClassColumns> out;
    if (!s.colname_off)
        return out;
    const uint64_t target = img.base + s.colname_off;
    for (uint64_t va = img.base + s.text_off; va + 4 <= img.base + s.text_end_off; va += 4)
    {
        if (!is_bl_to(img, va, target))
            continue;
        std::string name;
        for (int k = 1; k <= 4; k++)
        {
            uint64_t page = 0;
            uint32_t rd = 0;
            if (!adrp_at(img, va - 4 * k, page, rd))
                continue;
            uint64_t full = 0;
            if (!add_imm(img, va - 4 * k + 4, rd, full))
                continue;
            if (img.cstr(full, name))
                break;
            name.clear();
        }
        if (name.empty())
            continue;

        uint64_t slot = 0;
        for (int k = 1; k <= 8; k++)
        {
            uint32_t w = 0;
            if (!img.u32(va + 4 * k, w))
                break;
            uint32_t imm = 0, scale = 0;
            const uint32_t op = w & 0xFFC00000;
            if (op == 0xB9000000 && (w & 0x1F) == 0)
            {
                imm = (w >> 10) & 0xFFF;
                scale = 4;
            }
            else if (op == 0xF9000000 && (w & 0x1F) == 0)
            {
                imm = (w >> 10) & 0xFFF;
                scale = 8;
            }
            else if ((w & 0xFFE00C00) == 0xB8000000 && (w & 0x1F) == 0)
            {
                imm = (uint32_t)sign_extend((w >> 12) & 0x1FF, 9);
                scale = 4;
            }
            else
            {
                continue;
            }
            const uint32_t base = (w >> 5) & 0x1F;
            for (int b = 1; b <= 8; b++)
            {
                uint64_t page = 0;
                uint32_t rd = 0;
                if (!adrp_at(img, va + 4 * k - 4 * b, page, rd))
                    continue;
                if (rd == base)
                {
                    slot = page + (uint64_t)imm * scale;
                    break;
                }
            }
            break;
        }

        const uint32_t site = (uint32_t)(va - img.base);
        int idx = -1;
        for (size_t c = 0; c < boundaries.size(); c++)
        {
            if (boundaries[c].start > site)
                continue;
            if (idx < 0 || boundaries[c].start > boundaries[idx].start)
                idx = (int)c;
        }
        if (idx < 0)
            continue;
        if (out.empty() || out.back().start != boundaries[idx].start)
        {
            ClassColumns cc;
            cc.start = boundaries[idx].start;
            cc.cols = boundaries[idx].slots;
            cc.name = boundaries[idx].name;
            out.push_back(cc);
        }
        ClassColumn item;
        item.name = name;
        item.slot_va = slot;
        item.id = 0;
        if (slot)
            img.u32(slot, item.id);
        out.back().items.push_back(item);
    }
    return out;
}

std::vector<OwnFlag> scan_own_char_flags(const Image &img, const Seeds &s)
{
    std::vector<OwnFlag> out;
    if (!s.getbattle_off)
        return out;
    const uint64_t target = img.base + s.getbattle_off;
    for (uint64_t va = img.base + s.text_off; va + 4 <= img.base + s.text_end_off; va += 4)
    {
        if (!is_bl_to(img, va, target))
            continue;

        int R = -1, defK = -1;
        for (int k = 1; k <= 6; k++)
        {
            uint32_t w = 0;
            if (!img.u32(va + 4 * k, w))
                break;
            if ((w & 0xFFC00000) == 0xF9400000 && ((w >> 5) & 0x1F) == 0 &&
                ((w >> 10) & 0xFFF) * 8 == 0x28)
            {
                R = w & 0x1F;
                defK = k;
                break;
            }
        }
        if (R < 0)
            continue;

        for (int k = defK + 1; k <= defK + 64; k++)
        {
            uint64_t a = va + 4 * k;
            uint32_t w = 0;
            if (!img.u32(a, w))
                break;
            int dr = dest_reg(w);
            if (dr == R)
                break;
            if ((w & 0xFFC00000) == 0x39400000 && (int)((w >> 5) & 0x1F) == R)
            {
                out.push_back({(uint32_t)((w >> 10) & 0xFFF), 0, "ldrb"});
            }
            else if ((w & 0xFFC00000) == 0x79400000 && (int)((w >> 5) & 0x1F) == R)
            {
                out.push_back({(uint32_t)(((w >> 10) & 0xFFF) * 2), 0, "ldrh"});
            }
        }
    }
    return out;
}

} // namespace rcl
