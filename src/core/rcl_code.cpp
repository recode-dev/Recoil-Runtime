#include "rcl_find.h"
#include "rcl_syms.h"
#include "rcl_log.h"

#include <stdio.h>
#include <string.h>

namespace rcl
{

namespace
{

constexpr uint32_t kMagic64 = 0xFEEDFACFu;
constexpr uint32_t kSeg64 = 0x19u;
constexpr uint32_t kAdrpMask = 0x9F000000u;
constexpr uint32_t kAdrpVal = 0x90000000u;
constexpr uint32_t LLd = 0xF9400000u;
constexpr uint32_t LStr = 0xF9000000u;
constexpr uint32_t WLd = 0xB9400000u;
constexpr uint32_t WStr = 0xB9000000u;
constexpr uint32_t LdUr = 0xF8400000u;
constexpr uint32_t StUr = 0xF8000000u;
constexpr uint32_t Ret = 0xD65F03C0u;
constexpr uint32_t Pacibsp = 0xD503237Fu;

uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

bool is_prologue(uint32_t w)
{
    if (w == Pacibsp || w == 0xD503233Fu)
        return true;
    if ((w & 0xFFC07FFFu) == 0xA9007BFDu)
        return true;
    if ((w & 0xFFC003FFu) == 0xD10003FFu)
        return true;
    return false;
}

bool is_adrp(uint32_t w)
{
    return (w & kAdrpMask) == kAdrpVal;
}

uint64_t adrp_page(uint64_t va, uint32_t w)
{
    const uint64_t immlo = (w >> 29) & 0x3u;
    const uint64_t immhi = (w >> 5) & 0x7FFFFu;
    const uint64_t imm = ((immhi << 2) | immlo) << 12;
    return (va & ~0xFFFULL) + imm;
}

bool load_off(uint32_t w, uint32_t &rn, uint32_t &rt, int64_t &off)
{
    const uint32_t op = w & 0xFFC00000u;
    if (op == LLd || op == WLd || op == LStr || op == WStr)
    {
        const uint32_t scale = (op == LLd || op == LStr) ? 3u : 2u;
        rn = (w >> 5) & 0x1Fu;
        rt = w & 0x1Fu;
        off = (int64_t)((w >> 10) & 0xFFFu) << scale;
        return true;
    }
    if ((w & 0xFFE00000u) == LdUr || (w & 0xFFE00000u) == StUr)
    {
        rn = (w >> 5) & 0x1Fu;
        rt = w & 0x1Fu;
        off = (int64_t)((w >> 12) & 0x1FFu);
        if (off & 0x100)
            off -= 0x200;
        return (op != 0);
    }
    return false;
}

} // namespace

bool code_text_range(const Image &img, uint64_t &lo, uint64_t &hi)
{
    uint8_t hdr[32];
    uint32_t ncmds = 0;
    uint32_t sizeofcmds = 0;
    std::vector<uint8_t> lc;
    if (!img.read(img.ctx, img.base, hdr, sizeof hdr) || rd32(hdr) != kMagic64)
        return false;
    ncmds = rd32(hdr + 16);
    sizeofcmds = rd32(hdr + 20);
    if (!ncmds || ncmds > 4096 || sizeofcmds < 8 || sizeofcmds > 0x400000)
        return false;
    lc.resize(sizeofcmds);
    if (!img.read(img.ctx, img.base + sizeof hdr, lc.data(), sizeofcmds))
        return false;
    for (uint32_t p = 0, c = 0; c < ncmds && p + 8 <= sizeofcmds; c++)
    {
        const uint32_t cmd = rd32(lc.data() + p);
        const uint32_t size = rd32(lc.data() + p + 4);
        if (size < 8 || p + size > sizeofcmds)
            break;
        if (cmd == kSeg64 && size >= 72 && !memcmp(lc.data() + p + 8, "__TEXT", 6))
        {
            const uint64_t vmaddr = rd64(lc.data() + p + 24);
            const uint64_t fileoff = rd64(lc.data() + p + 40);
            const uint64_t filesize = rd64(lc.data() + p + 48);
            lo = img.base;
            hi = img.base + filesize;
            if (vmaddr && fileoff)
                hi = img.base + filesize;
            return hi > lo;
        }
        p += size;
    }
    return false;
}

uint64_t code_fn_start(const Image &img, uint64_t va, uint64_t lo)
{
    uint64_t p = va;
    uint64_t stop = va > lo + 0x2000 ? va - 0x2000 : lo;
    uint32_t w = 0;
    while (p >= stop + 4)
    {
        p -= 4;
        if (!img.u32(p, w))
            break;
        if (w == Ret)
            break;
        if (is_prologue(w))
            return p;
    }
    return 0;
}

uint64_t code_str_lookup(const Image &img, uint64_t cstr_va, uint64_t cstr_size, const char *needle, uint32_t *hits)
{
    std::vector<char> buf;
    const size_t n = (size_t)cstr_size;
    if (!cstr_va || n < 8 || n > 0x800000)
        return 0;
    buf.resize(n);
    if (!img.read(img.ctx, cstr_va, buf.data(), n))
        return 0;
    const size_t len = strlen(needle);
    uint64_t first = 0;
    uint32_t cnt = 0;
    for (size_t i = 0; i + len + 1 <= n; i++)
    {
        if (buf[i] != needle[0])
            continue;
        if (memcmp(buf.data() + i, needle, len) != 0)
            continue;
        if (buf[i + len] != 0)
            continue;
        if (!first)
            first = cstr_va + i;
        cnt++;
    }
    if (hits)
        *hits = cnt;
    return first;
}

void code_str_refs(const Image &img, uint64_t cstr_va, uint64_t cstr_size,
                   std::map<uint64_t, std::vector<uint64_t>> &out)
{
    uint64_t lo = 0;
    uint64_t hi = 0;
    std::vector<uint32_t> words;
    size_t n = 0;
    if (!cstr_va || !code_text_range(img, lo, hi))
        return;
    n = (size_t)((hi - lo) / 4);
    words.resize(n);
    if (!img.read(img.ctx, lo, words.data(), n * 4))
        return;
    for (size_t i = 0; i + 1 < n; i++)
    {
        const uint64_t va = lo + (uint64_t)i * 4;
        uint64_t target = 0;
        uint32_t rn = 0;
        uint32_t rt = 0;
        int64_t off = 0;
        if (!is_adrp(words[i]))
            continue;
        const uint64_t page = adrp_page(va, words[i]);
        const uint32_t w1 = words[i + 1];
        const uint32_t rd = words[i] & 0x1Fu;
        if ((w1 & 0x7F800000u) == 0x11000000u)
        {
            const uint32_t n1 = (w1 >> 5) & 0x1Fu;
            if (n1 != rd)
                continue;
            target = page + (uint64_t)((w1 >> 10) & 0xFFFu);
        }
        else if (load_off(w1, rn, rt, off) && rn == rd)
        {
            target = page + (uint64_t)off;
        }
        else
        {
            continue;
        }
        if (target < cstr_va || target >= cstr_va + cstr_size)
            continue;
        const uint64_t fn = code_fn_start(img, va, lo);
        if (fn)
            out[target].push_back(fn);
    }
}

void code_singletons(const Image &img, std::vector<uint64_t> &out)
{
    uint64_t lo = 0;
    uint64_t hi = 0;
    std::vector<uint32_t> w;
    size_t n = 0;
    size_t i = 0;
    if (!code_text_range(img, lo, hi))
        return;
    n = (size_t)((hi - lo) / 4);
    w.resize(n);
    if (!img.read(img.ctx, lo, w.data(), n * 4))
        return;
    for (i = 0; i + 2 < n; i++)
    {
        uint32_t rn = 0;
        uint32_t rt = 0;
        int64_t off = 0;
        if (!is_adrp(w[i]))
            continue;
        if (!load_off(w[i + 1], rn, rt, off))
            continue;
        if (rt != 0 || w[i + 2] != Ret)
            continue;
        out.push_back(adrp_page(lo + (uint64_t)i * 4, w[i]) + (uint64_t)off);
        if (out.size() >= 512)
            return;
    }
}

bool code_cstr_range(const Image &img, uint64_t &va, uint64_t &size)
{
    uint8_t hdr[32];
    uint32_t ncmds = 0;
    uint32_t sizeofcmds = 0;
    std::vector<uint8_t> lc;
    if (!img.read(img.ctx, img.base, hdr, sizeof hdr) || rd32(hdr) != kMagic64)
        return false;
    ncmds = rd32(hdr + 16);
    sizeofcmds = rd32(hdr + 20);
    if (!ncmds || ncmds > 4096 || sizeofcmds < 8 || sizeofcmds > 0x400000)
        return false;
    lc.resize(sizeofcmds);
    if (!img.read(img.ctx, img.base + sizeof hdr, lc.data(), sizeofcmds))
        return false;
    for (uint32_t p = 0, c = 0; c < ncmds && p + 8 <= sizeofcmds; c++)
    {
        const uint32_t cmd = rd32(lc.data() + p);
        const uint32_t sz = rd32(lc.data() + p + 4);
        if (sz < 8 || p + sz > sizeofcmds)
            break;
        if (cmd == kSeg64 && sz >= 72 && !memcmp(lc.data() + p + 8, "__TEXT", 6))
        {
            const uint64_t vmaddr = rd64(lc.data() + p + 24);
            const uint32_t nsects = rd32(lc.data() + p + 64);
            for (uint32_t s = 0; s < nsects && 72 + (s + 1) * 80 <= sz; s++)
            {
                const uint8_t *sec = lc.data() + p + 72 + (size_t)s * 80;
                if (memcmp(sec, "__cstring", 10))
                    continue;
                const uint64_t addr = rd64(sec + 32);
                const uint64_t ssize = rd64(sec + 40);
                if (!ssize)
                    break;
                va = img.base + (addr - vmaddr);
                size = ssize;
                return true;
            }
        }
        p += sz;
    }
    return false;
}

void code_profile(const Image &img, uint64_t rva, std::string &out)
{
    uint64_t lo = 0;
    uint64_t hi = 0;
    uint64_t va = 0;
    uint64_t page = 0;
    int have_page = 0;
    char buf[128];
    int n = 0;
    if (!code_text_range(img, lo, hi))
        return;
    va = img.base + rva;
    if (va < lo || va >= hi)
        return;
    for (n = 0; n < 400 && va < hi; n++, va += 4)
    {
        uint32_t w = 0;
        uint32_t rn = 0;
        uint32_t rt = 0;
        int64_t off = 0;
        if (!img.u32(va, w))
            return;
        if (n && w == Ret)
        {
            snprintf(buf, sizeof buf, "- ret\n");
            out += buf;
            return;
        }
        if (is_adrp(w))
        {
            page = adrp_page(va, w);
            have_page = 1;
            continue;
        }
        if (have_page && (w & 0x7F800000u) == 0x11000000u)
        {
            snprintf(buf, sizeof buf, "- adr add 0x%llx\n",
                     (unsigned long long)(page + ((w >> 10) & 0xFFFu)));
            out += buf;
            have_page = 0;
            continue;
        }
        if ((w & 0xFC000000u) == 0x94000000u)
        {
            int64_t imm = (int64_t)(w & 0x3FFFFFFu);
            if (imm & 0x2000000)
                imm -= 0x4000000;
            snprintf(buf, sizeof buf, "- bl 0x%llx\n",
                     (unsigned long long)((va + (uint64_t)(imm << 2)) - img.base));
            out += buf;
            have_page = 0;
            continue;
        }
        if (load_off(w, rn, rt, off))
        {
            if (rn <= 31 && rn >= 1 && off >= 0 && off <= 0x4000)
            {
                snprintf(buf, sizeof buf, "- mem x%u %s 0x%llx\n", rn,
                         ((w & 0x00C00000u) == 0x00400000u ||
                          (w & 0xFFE00000u) == StUr || (w & 0xFFFFFC00u) == 0xF8000000u)
                             ? "st"
                             : "ld",
                         (unsigned long long)off);
                out += buf;
            }
            have_page = 0;
            continue;
        }
        have_page = 0;
    }
    snprintf(buf, sizeof buf, "- cut at 0x%llx\n", (unsigned long long)(va - img.base));
    out += buf;
}

void code_resolve(const Image &img, const Seeds &s, Found &f, size_t &by_str, size_t &by_sing)
{
    static bool str_done = false;
    static std::map<uint64_t, std::vector<uint64_t>> refs;
    static std::vector<uint64_t> sings;
    static uint64_t cva = 0;
    static uint64_t csz = 0;
    uint64_t sva = s.cstr_va;
    uint64_t ssz = s.cstr_size;
    if (!cva && !str_done)
    {
        if (!sva || !ssz)
        {
            if (code_cstr_range(img, cva, csz))
            {
                sva = cva;
                ssz = csz;
                RCL_LOGLN("[code] cstring fallback 0x%llx size %llu", (unsigned long long)cva,
                          (unsigned long long)csz);
            }
        }
        else
        {
            cva = sva;
            csz = ssz;
        }
    }
    else if (cva)
    {
        sva = cva;
        ssz = csz;
    }
    char name[64];
    const char *p = f.key;
    const char *last = f.key;
    size_t len = 0;
    while (*p)
    {
        if (p[0] == '_' && p[1] == '_')
            last = p + 2;
        else if (p[0] == '_' && p[1] != '_' && p > f.key)
            last = p + 1;
        p++;
    }
    len = strlen(last);
    if (len >= 3 && len < sizeof name)
    {
        uint32_t hits = 0;
        const uint64_t sv = code_str_lookup(img, sva, ssz, last, &hits);
        if (sv && len >= 8 && hits == 1)
        {
            if (!str_done)
            {
                str_done = true;
                code_str_refs(img, sva, ssz, refs);
                RCL_LOGLN("[code] string refs %zu", refs.size());
            }
            std::map<uint64_t, std::vector<uint64_t>>::iterator it = refs.find(sv);
            if (it != refs.end() && !it->second.empty() && it->second.size() <= 8)
            {
                uint64_t best = it->second[0];
                for (size_t k = 1; k < it->second.size(); k++)
                {
                    if (it->second[k] < best)
                        best = it->second[k];
                }
                snprintf(name, sizeof name, "\"%s\" x%zu", last, it->second.size());
                f.value = best - img.base;
                f.src = "str";
                f.info = name;
                by_str++;
            }
        }
    }
    if (f.value)
        return;
    if (strstr(f.key, "instance") || strstr(f.key, "Instance") || strstr(f.key, "GlobalPtr") ||
        strstr(f.key, "tableArray") || strstr(f.key, "_Global"))
    {
        if (sings.empty())
        {
            code_singletons(img, sings);
            RCL_LOGLN("[code] singletons %zu", sings.size());
        }
        snprintf(name, sizeof name, "%zu singleton slots", sings.size());
        f.src = sings.empty() ? "todo" : "sing";
        f.info = name;
        if (!sings.empty())
            by_sing++;
    }
}

} // namespace rcl
