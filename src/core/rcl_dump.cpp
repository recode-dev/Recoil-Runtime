#include "rcl_dump.h"

#include "../scan/rcl_objects.h"
#include "../utils/rcl_out.h"
#include "rcl_find.h"
#include "rcl_log.h"

#include <set>
#include <string>
#include <vector>

namespace rcl
{

struct MissHint
{
    const char *key;
    uint32_t off;
    uint8_t kind;
};

static const MissHint kMiss[] = {
    {"BattleScreen_aimTargetId", 0xee4, 0},
    {"LogicSkillData_kind", 0x1ac, 0},
    {"LogicCharacterClient_body", 0x3e8, 1},
    {"LogicCharacterClientOwn_speedBuff", 0x1fc, 0},
    {"CharData_brawlerId", 0x18, 0},
    {"HeroData_namePtr", 0x48, 1},
    {"LogicProjectileClient_ctor", 0, 2},
    {"LogicProjectileClient_destruct", 0, 2},
    {"BattleScreen_activateSkill", 0, 3},
    {"BattleScreen_getClosestTargetForAutoshoot", 0, 3},
    {"LogicTile__setData", 0, 3},
    {"SkillCommandTypeTable", 0, 3},
};

void dump_index(const Image &img)
{
    std::string t = "# Recoil-Runtime dump\n\n";
    t += out_fmt("- base: `0x%llx`\n", (unsigned long long)img.base);
    t += out_fmt("- image_vmsize: `0x%llx`\n\n", (unsigned long long)img.image_vmsize);
    t += "sections: `anchors`, `properties`, `columns`, `vtables`, `ctors`, `targets`, `missing`\n";
    out_write_root("index", t);
}

void dump_anchors(const Image &img, const Seeds &s)
{
    std::string t;
    t += "# anchors\n\n";
    t += out_fmt("- base: `0x%llx`\n", (unsigned long long)img.base);
    t += out_fmt("- text: `0x%llx` .. `0x%llx`\n", (unsigned long long)s.text_off,
                 (unsigned long long)s.text_end_off);
    t += out_fmt("- image_vmsize: `0x%llx`\n", (unsigned long long)img.image_vmsize);
    t += out_fmt("- getBattle: `0x%llx` (score %u)\n", (unsigned long long)s.getbattle_off,
                 s.getbattle_score);
    t += out_fmt("- getProperty: `0x%llx` (score %u)\n", (unsigned long long)s.propget_off,
                 s.propget_score);
    t += out_fmt("- getColumnName: `0x%llx` (score %u)\n", (unsigned long long)s.colname_off,
                 s.colname_score);
    t += out_fmt("- cstring table: `0x%llx` (%llu)\n", (unsigned long long)s.cstr_va,
                 (unsigned long long)s.cstr_size);
    t += out_fmt("- auto_found: %d\n", s.auto_found ? 1 : 0);
    out_write("anchors", "anchors", t);
    RCL_LOGLN("[dump] anchors");
}

void dump_properties(const Image &img, const Seeds &s)
{
    std::vector<PropSite> v = scan_property_sites(img, s);
    std::string t = out_fmt("# property sites\n\nsites: %zu\n\n| field | id | width | kind | site |\n", v.size());
    t += "|---|---|---|---|---|\n";
    for (size_t i = 0; i < v.size() && i < 4000; i++)
    {
        t += out_fmt("| `+0x%04x` | `0x%02x` | %u | %s | `0x%llx` |\n", v[i].field, v[i].id,
                     (unsigned)v[i].width, v[i].kind, (unsigned long long)v[i].site);
    }
    out_write("properties", "fields", t);
    RCL_LOGLN("[dump] properties %zu", v.size());
}

void dump_columns(const Image &img, const Seeds &s)
{
    std::vector<ColumnSite> v = scan_column_sites(img, s);
    std::string t = out_fmt("# column names\n\nsites: %zu\n\n", v.size());
    for (size_t i = 0; i < v.size() && i < 8000; i++)
        t += out_fmt("- `0x%llx`  \"%s\"\n", (unsigned long long)v[i].slot_va, v[i].name.c_str());
    out_write("columns", "columns", t);
    RCL_LOGLN("[dump] columns %zu", v.size());
}

static std::vector<VTable> g_vt;

void dump_vtables(const Image &img)
{
    std::vector<VTable> &v = g_vt;
    v = scan_vtables(img);
    std::string idx = out_fmt("# vtables\n\ncandidates: %zu\n\n| vtable | slots | first | name guess |\n", v.size());
    idx += "|---|---|---|---|\n";
    size_t files = 0;
    for (size_t i = 0; i < v.size(); i++)
    {
        idx += out_fmt("| `0x%llx` | %u | `0x%llx` | %s |\n", (unsigned long long)v[i].addr, v[i].slots,
                       (unsigned long long)v[i].first, v[i].guess.empty() ? "-" : v[i].guess.c_str());
        if (files < 8000)
        {
            std::string t = out_fmt("# vtable 0x%llx\n\n- slots: %u\n- name guess: %s\n\n",
                                    (unsigned long long)v[i].addr, v[i].slots,
                                    v[i].guess.empty() ? "-" : v[i].guess.c_str());
            for (int j = -2; j <= 6; j++)
            {
                uint64_t q = 0;
                if (img.read(img.ctx, v[i].addr + (int64_t)j * 8, &q, 8))
                    t += out_fmt("- raw[%d] `0x%llx`\n", j, (unsigned long long)q);
            }
            for (uint32_t k = 0; k < v[i].slots && k < 512; k++)
            {
                uint64_t p = 0;
                if (img.read(img.ctx, v[i].addr + (uint64_t)k * 8, &p, 8))
                    t += out_fmt("- [%u] `0x%llx`\n", k, (unsigned long long)p);
            }
            std::string nm = out_fmt("vtable-%llx", (unsigned long long)v[i].addr);
            out_write("vtables", nm.c_str(), t);
            files++;
        }
    }
    out_write("vtables", "index", idx);
    RCL_LOGLN("[dump] vtables %zu (files %zu)", v.size(), files);
}

void dump_ctors(const Image &img)
{
    std::vector<VTable> &vt = g_vt;
    std::set<uint64_t> vs;
    std::vector<Ctor> v;
    for (size_t k = 0; k < vt.size(); k++)
        vs.insert(vt[k].addr);
    v = scan_ctors(img, vs);
    std::string idx = out_fmt("# ctors\n\ncandidates: %zu\n\n| ctor | vtable | class | store |\n|---|---|---|---|\n", v.size());
    size_t files = 0;
    for (size_t i = 0; i < v.size(); i++)
    {
        std::string cn = vtable_name(img, v[i].vtable);
        idx += out_fmt("| `0x%llx` | `0x%llx` | %s | `0x%llx` |\n", (unsigned long long)v[i].fn,
                       (unsigned long long)v[i].vtable, cn.empty() ? "-" : cn.c_str(),
                       (unsigned long long)v[i].store_at);
        if (files < 8000)
        {
            std::string t = out_fmt("# ctor 0x%llx\n\n- vtable written: `0x%llx`\n- at: `0x%llx`\n\n",
                                    (unsigned long long)v[i].fn, (unsigned long long)v[i].vtable,
                                    (unsigned long long)v[i].store_at);
            std::string nm = out_fmt("ctor-%llx", (unsigned long long)v[i].fn);
            out_write("ctors", nm.c_str(), t);
            files++;
        }
    }
    out_write("ctors", "index", idx);
    RCL_LOGLN("[dump] ctors %zu (files %zu)", v.size(), files);
}

void dump_targets(const Image &img, const Seeds &s)
{
    FindResult fr = find_all(img, s);
    size_t amb = 0;
    for (size_t i = 0; i < kTargetCount; i++)
        if (kTargets[i].seed == 0 && kTargets[i].cls && kTargets[i].cls[0])
            amb++;
    std::string t = out_fmt("# targets\n\nresolved: %zu/%zu\naliases: %zu\nambiguous (no resolver): %zu\nno class: %zu\n\n",
                            fr.resolved, kTargetCount, fr.duplicated, amb, kTargetCount - fr.resolved - fr.duplicated - amb);
    t += "| key | value | source | alias of |\n|---|---|---|---|\n";
    for (size_t i = 0; i < fr.items.size(); i++)
    {
        const Found &f = fr.items[i];
        t += out_fmt("| `%s` | `0x%llx` | %s | %s |\n", f.key, (unsigned long long)f.value, f.src,
                     f.alias_of ? f.alias_of : "-");
    }
    out_write("targets", "resolved", t);
    std::string a = "# ambiguous targets (class known, resolver absent)\n\n";
    for (size_t i = 0; i < kTargetCount; i++)
        if (kTargets[i].seed == 0 && kTargets[i].cls && kTargets[i].cls[0])
            a += out_fmt("- `%s`  (class `%s`)\n", kTargets[i].key, kTargets[i].cls);
    out_write("targets", "ambiguous", a);
    RCL_LOGLN("[dump] targets %zu/%zu amb %zu", fr.resolved, kTargetCount, amb);
}

void dump_missing(const Image &img)
{
    std::vector<Leaf> leafs = scan_leaf_getters(img);
    for (size_t i = 0; i < sizeof kMiss / sizeof kMiss[0]; i++)
    {
        const MissHint &h = kMiss[i];
        std::string t = out_fmt("# %s\n\n", h.key);
        if (h.kind == 2)
        {
            std::set<uint64_t> vs;
            std::vector<Ctor> cs;
            size_t picked = 0;
            for (size_t k = 0; k < g_vt.size(); k++)
                vs.insert(g_vt[k].addr);
            cs = scan_ctors(img, vs);
            t += out_fmt("all ctors: %zu; those whose vtable class matches the key:\n\n", cs.size());
            for (size_t k = 0; k < cs.size(); k++)
            {
                std::string cn = vtable_name(img, cs[k].vtable);
                if (cn.empty() || cn.find(h.key + 0) != std::string::npos)
                    continue;
                const bool hit = std::string(h.key).find(cn) != std::string::npos;
                if (!hit && picked > 32)
                    continue;
                t += out_fmt("- `0x%llx`  vtable `0x%llx`  class %s  store@`0x%llx`\n",
                             (unsigned long long)cs[k].fn, (unsigned long long)cs[k].vtable,
                             cn.c_str(), (unsigned long long)cs[k].store_at);
                picked++;
            }
            if (!picked)
                t += "- none matched by class name (see ctors/index.md for the full list)\n";
        }
        else if (h.kind == 3)
        {
            t += "no structural resolver for this one: needs a call-site analysis\n";
            t += "(who calls it / what it references), or a labeled build.\n";
        }
        else
        {
            t += out_fmt("hint offset (from REvengeBS, not confirmed for this build): `+0x%x`\n\n"
                         "leaf getters returning this member: %s\n\n",
                         h.off, "");
            size_t n = 0;
            for (size_t k = 0; k < leafs.size(); k++)
            {
                if (leafs[k].off != h.off)
                    continue;
                if (h.kind == 1 && !leafs[k].load_x0)
                    continue;
                if (h.kind == 0 && leafs[k].load_x0)
                    continue;
                t += out_fmt("- `0x%llx`  w%u\n", (unsigned long long)leafs[k].fn, (unsigned)leafs[k].width);
                n++;
            }
            if (!n)
                t += "- none\n";
        }
        out_write("missing", h.key, t);
    }
    RCL_LOGLN("[dump] missing %zu", sizeof kMiss / sizeof kMiss[0]);
}

static bool rdany(const Image &img, uint64_t va, void *dst, size_t n)
{
    if (img.read_raw)
        return img.read_raw(img.ctx, va, dst, n);
    return img.read(img.ctx, va, dst, n);
}

void dump_colmap(const Image &img, const Seeds &s)
{
    const uint64_t arr = img.base + 0x1154f08ULL;
    std::string root = out_fmt("# table array probe\n\n- arr: `0x%llx`\n\n## raw slots\n\n",
                               (unsigned long long)arr);
    std::string idx = "# column map\n\n";
    for (int i = 0; i < 24; i++)
    {
        uint64_t w = 0;
        if (rdany(img, arr + (uint64_t)i * 8, &w, 8))
            root += out_fmt("- slot[%d] = `0x%llx`\n", i, (unsigned long long)w);
    }
    for (int i = 0; i < 24; i++)
    {
        uint64_t t = 0;
        uint64_t vt = 0;
        uint64_t cnt = 0;
        uint64_t a = 0;
        uint64_t b = 0;
        uint64_t c = 0;
        std::string nm;
        if (!rdany(img, arr + (uint64_t)i * 8, &t, 8) || !t)
            continue;
        root += out_fmt("\n## slot %d  table `0x%llx`\n\n", i, (unsigned long long)t);
        if (rdany(img, t, &vt, 8))
            root += out_fmt("- *(table) = `0x%llx`\n", (unsigned long long)vt);
        if (rdany(img, t + 0x50, &cnt, 8))
            root += out_fmt("- *(table+0x50) = `0x%llx`\n", (unsigned long long)cnt);
        if (!rdany(img, t + 0x58, &a, 8) || !a)
        {
            root += "- *(table+0x58) = null\n";
            continue;
        }
        root += out_fmt("- *(table+0x58) = `0x%llx`\n", (unsigned long long)a);
        if (rdany(img, a, &b, 8))
            root += out_fmt("- *(csv+0x00) = `0x%llx`\n", (unsigned long long)b);
        if (rdany(img, a + 8, &b, 8))
            root += out_fmt("- *(csv+0x08) = `0x%llx`\n", (unsigned long long)b);
        if (rdany(img, a + 0x18, &b, 8))
            root += out_fmt("- *(csv+0x18) = `0x%llx`\n", (unsigned long long)b);
        if (rdany(img, a + 0x58, &b, 8) && b && rdany(img, b + 0x18, &c, 8) && c)
        {
            uint64_t sc = c + 0x30;
            uint32_t len = 0;
            uint64_t data = 0;
            root += out_fmt("- name-scstring `0x%llx`\n", (unsigned long long)sc);
            if (img.u32(sc + 4, len) && len > 0 && len < 64)
            {
                if (len <= 7)
                {
                    char buf[72];
                    if (rdany(img, sc + 8, buf, len))
                    {
                        buf[len] = 0;
                        nm = std::string(buf);
                    }
                }
                else if (rdany(img, sc + 8, &data, 8) && data)
                {
                    std::string tmp;
                    if (img.cstr(data, tmp))
                        nm = tmp;
                }
                root += out_fmt("- name = \"%s\"\n", nm.c_str());
            }
        }
        idx += out_fmt("- [%d] table `0x%llx` csv `0x%llx` name \"%s\"\n", i,
                       (unsigned long long)t, (unsigned long long)a, nm.c_str());
    }
    out_write("columns", "map-root", root);
    out_write("columns", "map-index", idx);
    RCL_LOGLN("[dump] column map probe");
}

void dump_all(const Image &img, const Seeds &s)
{
    dump_index(img);
    dump_anchors(img, s);
    dump_properties(img, s);
    dump_columns(img, s);
    dump_colmap(img, s);
    dump_vtables(img);
    dump_ctors(img);
    dump_targets(img, s);
    dump_missing(img);
}

} // namespace rcl
