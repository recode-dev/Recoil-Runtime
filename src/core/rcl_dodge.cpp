#include "rcl_dodge.h"
#include "rcl_syms.h"
#include "rcl_infer.h"
#include "rcl_log.h"

#include <map>
#include <stdio.h>
#include <string>
#include <vector>

namespace rcl
{

struct DodgeTarget
{
    uint32_t off;
    const char *tag;
};

static const DodgeTarget kDodgeTargets[] = {
    {0x254, "c254"},
    {0x258, "c258"},
    {0x25c, "c25c"},
    {0x1d4, "proj_angle"},
};

static int dodge_access(uint32_t w, uint32_t &off, uint32_t &width)
{
    uint32_t base = w & 0xFFC00000u;
    uint32_t scale = 4;
    switch (base)
    {
    case 0xB9400000u:
    case 0xB9000000u:
    case 0xBD400000u:
    case 0xBD000000u:
        scale = 4;
        break;
    case 0xF9400000u:
    case 0xF9000000u:
    case 0xFD400000u:
    case 0xFD000000u:
        scale = 8;
        break;
    case 0x39400000u:
    case 0x39000000u:
        scale = 1;
        break;
    case 0x79400000u:
    case 0x79000000u:
        scale = 2;
        break;
    case 0x3D400000u:
    case 0x3D000000u:
        scale = 16;
        break;
    default:
        return 0;
    }
    if ((w & 0x00C00000u) == 0x00400000u && base != 0x3D400000u && base != 0x3D000000u)
        scale *= 2;
    if (((w >> 5) & 0x1Fu) == 31u)
        return 0;
    off = ((w >> 10) & 0xFFFu) * scale;
    width = scale;
    return (base & 0x00400000u) ? 2 : 1;
}

void dodge_sites(const Image &img, const Seeds &s)
{
    uint64_t lo = 0, hi = 0;
    if (!code_text_range(img, lo, hi))
        return;
    const char *dir = log_dir();
    if (!dir || !*dir)
        return;
    char path[1024];
    snprintf(path, sizeof path, "%s/dodge.log", dir);
    FILE *f = fopen(path, "a");
    if (!f)
        return;

    std::map<uint64_t, std::string> names;
    const std::vector<InferredName> &in = infer_cached(img, s);
    for (size_t i = 0; i < in.size(); i++)
        names[in[i].rva] = in[i].name;

    const size_t nt = sizeof(kDodgeTargets) / sizeof(kDodgeTargets[0]);
    size_t hits = 0;
    fprintf(f, "[dodge] pass base=0x%llx text=0x%llx..0x%llx targets=%zu names=%zu\n",
            (unsigned long long)img.base, (unsigned long long)(lo - img.base),
            (unsigned long long)(hi - img.base), nt, names.size());

    for (uint64_t va = lo; va + 4 <= hi; va += 4)
    {
        uint32_t w = 0, off = 0, width = 0;
        if (!img.u32(va, w))
            continue;
        int kind = dodge_access(w, off, width);
        if (!kind)
            continue;
        const DodgeTarget *t = nullptr;
        for (size_t i = 0; i < nt; i++)
        {
            if (kDodgeTargets[i].off == off)
            {
                t = &kDodgeTargets[i];
                break;
            }
        }
        if (!t)
            continue;
        uint64_t fn = code_fn_start(img, va, lo);
        const char *nm = "";
        std::map<uint64_t, std::string>::iterator it = names.find(fn - img.base);
        if (it != names.end())
            nm = it->second.c_str();
        fprintf(f, "[dodge] %s %-10s site=0x%llx fn=0x%llx w=%u name=%s\n",
                kind == 2 ? "wr" : "rd", t->tag, (unsigned long long)(va - img.base),
                (unsigned long long)(fn - img.base), width, nm);
        hits++;
    }
    fprintf(f, "[dodge] done hits=%zu\n", hits);
    fclose(f);
    RCL_LOGLN("[dodge] %zu sites written to dodge.log", hits);
}

} // namespace rcl
