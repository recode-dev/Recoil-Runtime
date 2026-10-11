#include "rcl_syms.h"
#include "rcl_log.h"

#include <ctype.h>
#include <string.h>

namespace rcl
{

namespace
{

constexpr uint32_t kMagic64 = 0xFEEDFACFu;
constexpr uint32_t kLC_SEGMENT_64 = 0x19u;
constexpr uint32_t kLC_SYMTAB = 0x02u;
constexpr uint32_t kNlist64Size = 16u;

struct Seg
{
    uint64_t fileoff = 0;
    uint64_t filesize = 0;
    uint64_t vmaddr = 0;
    uint64_t vmsize = 0;
};

uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint64_t be64(const uint8_t *p)
{
    return (uint64_t)be32(p) | ((uint64_t)be32(p + 4) << 32);
}

uint64_t file_to_va(const Seg *segs, int n, uint64_t off, uint64_t load_base)
{
    for (int i = 0; i < n; i++)
    {
        if (off < segs[i].fileoff || off >= segs[i].fileoff + segs[i].filesize)
            continue;
        return load_base + (segs[i].vmaddr - segs[0].vmaddr) + (off - segs[i].fileoff);
    }
    return 0;
}

} // namespace

void norm_key(const char *in, std::string &out)
{
    out.clear();
    if (!in)
        return;
    size_t i = 0;
    while (in[i] == '_')
        i++;
    for (; in[i]; i++)
    {
        const unsigned char c = (unsigned char)in[i];
        if (c == '_')
            continue;
        if (c == '@' || c == '$' || c == '.')
            break;
        if (!isalnum(c) && c != '<' && c != '>' && c != ':')
            continue;
        out.push_back((char)tolower(c));
    }
}

uint32_t load_symbols(const Image &img, std::vector<Sym> &out)
{
    uint8_t hdr[32];
    Seg segs[32];
    int nsegs = 0;
    std::vector<uint8_t> lc;
    uint32_t ncmds = 0;
    uint32_t sizeofcmds = 0;
    uint32_t symoff = 0;
    uint32_t nsyms = 0;
    uint32_t stroff = 0;
    uint32_t strsize = 0;
    bool have_symtab = false;
    uint64_t unslid = 0;
    if (!img.read(img.ctx, img.base, hdr, sizeof hdr))
        return 0;
    if (be32(hdr) != kMagic64)
        return 0;
    ncmds = be32(hdr + 16);
    sizeofcmds = be32(hdr + 20);
    if (ncmds == 0 || ncmds > 4096 || sizeofcmds < 8 || sizeofcmds > 0x400000)
        return 0;
    lc.resize(sizeofcmds);
    if (!img.read(img.ctx, img.base + sizeof hdr, lc.data(), sizeofcmds))
        return 0;
    for (uint32_t p = 0, c = 0; c < ncmds && p + 8 <= sizeofcmds; c++)
    {
        const uint32_t cmd = be32(lc.data() + p);
        const uint32_t size = be32(lc.data() + p + 4);
        if (size < 8 || p + size > sizeofcmds)
            break;
        if (cmd == kLC_SEGMENT_64 && size >= 72 && nsegs < 32)
        {
            Seg s;
            s.vmaddr = be64(lc.data() + p + 24);
            s.vmsize = be64(lc.data() + p + 32);
            s.fileoff = be64(lc.data() + p + 40);
            s.filesize = be64(lc.data() + p + 48);
            if (s.vmsize && s.filesize)
                segs[nsegs++] = s;
        }
        else if (cmd == kLC_SYMTAB && size >= 24)
        {
            symoff = be32(lc.data() + p + 8);
            nsyms = be32(lc.data() + p + 12);
            stroff = be32(lc.data() + p + 16);
            strsize = be32(lc.data() + p + 20);
            have_symtab = true;
        }
        p += size;
    }
    if (!nsegs || !have_symtab || !nsyms || !strsize || nsyms > 1000000u || strsize > 0x4000000u)
    {
        RCL_LOGLN("[sym] no usable symtab (nsegs=%d syms=%u strsize=%u)", nsegs, nsyms, strsize);
        return 0;
    }
    unslid = segs[0].vmaddr;
    for (int i = 1; i < nsegs; i++)
    {
        if (segs[i].vmaddr < unslid)
            unslid = segs[i].vmaddr;
    }
    const uint64_t load_base = img.base;
    const uint64_t sym_va = file_to_va(segs, nsegs, symoff, load_base);
    const uint64_t str_va = file_to_va(segs, nsegs, stroff, load_base);
    if (!sym_va || !str_va)
    {
        RCL_LOGLN("[sym] symtab outside mapped segments");
        return 0;
    }
    std::vector<char> str;
    str.resize(strsize);
    if (!img.read(img.ctx, str_va, str.data(), strsize))
    {
        RCL_LOGLN("[sym] strtab unreadable");
        return 0;
    }
    out.reserve(nsyms < 200000u ? nsyms : 200000u);
    for (uint32_t i = 0; i < nsyms && out.size() < 200000u; i++)
    {
        uint8_t e[kNlist64Size];
        if (!img.read(img.ctx, sym_va + (uint64_t)i * kNlist64Size, e, sizeof e))
            break;
        const uint32_t strx = be32(e);
        const uint8_t ntype = e[4];
        const uint64_t nvalue = be64(e + 8);
        if (strx == 0 || strx >= strsize || (ntype & 0xE0u) == 0xE0u)
            continue;
        const char *nm = str.data() + strx;
        if (!nm[0] || (unsigned char)nm[0] < 32)
            continue;
        size_t len = strnlen(nm, 512);
        if (len < 2 || len >= 512)
            continue;
        Sym s;
        s.name.assign(nm, len);
        if (nvalue >= unslid && nvalue - unslid < img.vmsize)
            s.rva = nvalue - unslid;
        else if (nvalue >= load_base && nvalue - load_base < img.vmsize)
            s.rva = nvalue - load_base;
        else
            continue;
        if (!s.rva)
            continue;
        out.push_back(s);
    }
    RCL_LOGLN("[sym] %zu symbols (nsyms=%u, unslid=0x%llx)", out.size(), nsyms,
              (unsigned long long)unslid);
    return (uint32_t)out.size();
}

int64_t sym_match(const std::vector<Sym> &syms, const std::vector<std::string> &norm, const char *key)
{
    std::string kn;
    std::vector<std::string> parts;
    int64_t best = -1;
    size_t best_len = 0;
    size_t i = 0;
    if (syms.empty() || norm.size() != syms.size())
        return -1;
    norm_key(key, kn);
    if (kn.size() < 4)
        return -1;
    {
        std::string cur;
        const char *p = key;
        while (*p == '_')
            p++;
        for (;; p++)
        {
            if (*p && *p != '_')
            {
                cur.push_back(*p);
                continue;
            }
            std::string n;
            norm_key(cur.c_str(), n);
            if (n.size() >= 3)
                parts.push_back(n);
            cur.clear();
            if (!*p)
                break;
        }
    }
    for (i = 0; i < norm.size(); i++)
    {
        if (norm[i] == kn)
            return (int64_t)i;
    }
    if (kn.size() >= 6)
    {
        for (i = 0; i < norm.size(); i++)
        {
            const std::string &n = norm[i];
            if (n.size() < kn.size() || n.find(kn) == std::string::npos)
                continue;
            if (best < 0 || n.size() < best_len)
            {
                best = (int64_t)i;
                best_len = n.size();
            }
        }
    }
    if (best >= 0)
        return best;
    if (parts.size() < 2)
        return -1;
    for (i = 0; i < norm.size(); i++)
    {
        const std::string &n = norm[i];
        size_t pos = 0;
        bool all = true;
        for (size_t k = 0; k < parts.size(); k++)
        {
            size_t at = n.find(parts[k], pos);
            if (at == std::string::npos)
            {
                all = false;
                break;
            }
            pos = at + parts[k].size();
        }
        if (!all)
            continue;
        if (best < 0 || n.size() < best_len)
        {
            best = (int64_t)i;
            best_len = n.size();
        }
    }
    return best;
}

} // namespace rcl
