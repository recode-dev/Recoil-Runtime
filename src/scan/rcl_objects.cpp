#include "rcl_objects.h"

#include <algorithm>
#include <set>

namespace rcl
{

static bool exec_ptr(const Image &img, uint64_t va, uint64_t lo, uint64_t hi, uint64_t &out)
{
    uint64_t v = 0;
    if (!img.read(img.ctx, va, &v, 8) || v == 0)
        return false;
    if (v < lo || v >= hi)
        return false;
    out = v;
    return true;
}

static bool leaf_at(const Image &img, uint64_t va, uint32_t &off, uint8_t &width, bool &is_x0)
{
    uint32_t a = 0;
    uint32_t b = 0;
    if (!img.u32(va, a) || !img.u32(va + 4, b) || b != 0xD65F03C0u)
        return false;
    if ((a & 0xFFC00000u) == 0xB9400000u || (a & 0xFFC00000u) == 0xF9400000u)
    {
        if ((a & 0x1Fu) != 0 || ((a >> 5) & 0x1Fu) != 0)
            return false;
        const bool wide = (a & 0xFFC00000u) == 0xF9400000u;
        off = ((a >> 10) & 0xFFFu) * (wide ? 8u : 4u);
        width = wide ? 8 : 4;
        is_x0 = wide;
        return true;
    }
    return false;
}

std::vector<Leaf> scan_leaf_getters(const Image &img)
{
    std::vector<Leaf> out;
    uint64_t lo = 0;
    uint64_t hi = 0;
    if (!macho_text_range(img, lo, hi))
        return out;
    for (uint64_t va = lo; va + 8 <= hi; va += 4)
    {
        Leaf l;
        if (leaf_at(img, va, l.off, l.width, l.load_x0))
        {
            l.fn = va;
            out.push_back(l);
        }
    }
    return out;
}

static bool value_before(const Image &img, uint64_t va, uint32_t want_reg, int back, uint64_t &out)
{
    for (int i = 1; i <= back; i++)
    {
        uint64_t at = va - (uint64_t)i * 4;
        uint32_t w = 0;
        uint32_t nx = 0;
        if (!img.u32(at, w))
            return false;
        if ((w & 0x9F00001Fu) != 0x90000000u || (w & 0x1Fu) != want_reg)
            continue;
        int64_t hi = ((int64_t)((w >> 5) & 0x7FFFFu) << 2) | (int64_t)((w >> 29) & 3u);
        if (hi & (1 << 20))
            hi -= 1 << 21;
        uint64_t page = (at & ~0xFFFULL) + ((uint64_t)hi << 12);
        if (!img.u32(at + 4, nx))
            return false;
        if ((nx & 0xFFC00000u) == 0x91000000u && ((nx >> 5) & 0x1Fu) == want_reg)
        {
            out = page + (uint64_t)((nx >> 10) & 0xFFFu);
            return true;
        }
        if ((nx & 0xFFC00000u) == 0xF9400000u && ((nx >> 5) & 0x1Fu) == want_reg)
        {
            uint64_t slot = page + (uint64_t)(((nx >> 10) & 0xFFFu) * 8u);
            uint64_t v = 0;
            if (img.read(img.ctx, slot, &v, 8) && v)
            {
                out = v;
                return true;
            }
        }
        return false;
    }
    return false;
}

static uint64_t fn_start(const Image &img, uint64_t at, uint64_t lo)
{
    for (uint64_t back = 4; back < 0x400; back += 4)
    {
        uint64_t p = at - back;
        uint32_t w = 0;
        if (p < lo || !img.u32(p, w))
            return 0;
        if (w == 0xD503237Fu || (w & 0xFFC003FFu) == 0xA98003FFu || (w & 0xFFC003FFu) == 0xA90003FFu)
            return p;
        if (w == 0xD65F03C0u)
            return 0;
    }
    return 0;
}

static std::string guess_name(const Image &img, uint64_t base, uint64_t lo, uint64_t hi)
{
    for (int i = 0; i < 64; i++)
    {
        uint64_t p = 0;
        std::string s;
        if (!img.read(img.ctx, base + (uint64_t)i * 8, &p, 8) || !p)
            continue;
        if (p >= lo && p < hi)
            continue;
        if (img.cstr(p, s) && s.size() >= 3 && s.size() <= 64 && s.find(' ') == std::string::npos)
            return s;
    }
    return std::string();
}

static void push_run(const Image &img, uint64_t start, uint64_t slots, uint64_t lo, uint64_t hi,
                     std::vector<VTable> &out)
{
    VTable v;
    v.addr = start;
    v.slots = (uint32_t)slots;
    img.read(img.ctx, start, &v.first, 8);
    v.guess = guess_name(img, start, lo, hi);
    out.push_back(v);
}

std::vector<VTable> scan_vtables(const Image &img)
{
    std::vector<VTable> out;
    uint64_t lo = 0;
    uint64_t hi = 0;
    uint64_t dlo[8];
    uint64_t dhi[8];
    int dn = 0;
    if (!macho_text_range(img, lo, hi))
        return out;
    if (!macho_data_ranges(img, dlo, dhi, 8, dn))
        return out;
    for (int d = 0; d < dn; d++)
    {
        uint64_t run = 0;
        for (uint64_t va = dlo[d]; va + 8 <= dhi[d]; va += 8)
        {
            uint64_t slot = 0;
            if (exec_ptr(img, va, lo, hi, slot))
            {
                run++;
                continue;
            }
            if (run >= 3)
                push_run(img, va - run * 8, run, lo, hi, out);
            run = 0;
        }
        if (run >= 3)
            push_run(img, dhi[d] - run * 8, run, lo, hi, out);
    }
    std::sort(out.begin(), out.end(), [](const VTable &a, const VTable &b) { return a.addr < b.addr; });
    return out;
}

std::vector<Ctor> scan_ctors(const Image &img, uint64_t vtable_hint)
{
    std::vector<Ctor> out;
    std::set<uint64_t> seen;
    uint64_t lo = 0;
    uint64_t hi = 0;
    if (!macho_text_range(img, lo, hi))
        return out;
    for (uint64_t va = lo; va + 20 <= hi; va += 4)
    {
        uint32_t w = 0;
        uint64_t val = 0;
        uint64_t f = 0;
        if (!img.u32(va, w) || (w & 0xFFC00000u) != 0xF9000000u || ((w >> 5) & 0x1Fu) != 0)
            continue;
        const uint32_t reg = w & 0x1Fu;
        if (reg > 2 || !value_before(img, va, reg, 3, val))
            continue;
        if (vtable_hint && val != vtable_hint)
            continue;
        f = fn_start(img, va, lo);
        if (!f || seen.count(f))
            continue;
        seen.insert(f);
        Ctor c;
        c.fn = f;
        c.vtable = val;
        c.store_at = va;
        out.push_back(c);
    }
    return out;
}

} // namespace rcl
