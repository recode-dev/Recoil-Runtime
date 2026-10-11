#include "rcl_dump.h"

#include "../scan/rcl_objects.h"
#include "../utils/rcl_out.h"
#include "rcl_find.h"
#include "rcl_log.h"

#include <set>
#include <string>
#include <string.h>
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
    t += "sections: `anchors`, `properties`, `columns/map-all`, `vtables`, `ctors`, `targets`,"
         " `missing`\n";
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

static bool rdany_3(const Image &img, uint64_t va, void *dst, size_t n)
{
    if (img.read_raw)
        return img.read_raw(img.ctx, va, dst, n);
    return img.read(img.ctx, va, dst, n);
}

static bool win_ok_3(uint64_t va)
{
    return va >= 0x100000000ULL && va < 0x400000000ULL && (va & 7) == 0;
}

static std::string rstr_3(const Image &img, uint64_t va, size_t maxn)
{
    char buf[64];
    size_t n = maxn < sizeof buf - 1 ? maxn : sizeof buf - 1;
    if (!win_ok_3(va) || n < 2)
        return std::string();
    if (!rdany_3(img, va, buf, n))
        return std::string();
    buf[n] = 0;
    for (size_t i = 0; i < n; i++)
    {
        if (buf[i] == 0)
        {
            if (i < 2)
                return std::string();
            return std::string(buf, i);
        }
        if ((unsigned char)buf[i] < 32 || (unsigned char)buf[i] > 127)
            return std::string();
    }
    return std::string();
}

static std::string inl_3(uint64_t v)
{
    unsigned char b[8];
    std::string out;
    memcpy(b, &v, sizeof b);
    for (int i = 0; i < 8; i++)
    {
        if (b[i] == 0)
            break;
        if (b[i] < 32 || b[i] > 127)
            return std::string();
        out.push_back((char)b[i]);
    }
    return out;
}

static std::string scstr_3(const Image &img, uint64_t base)
{
    uint64_t lenw = 0;
    uint64_t data = 0;
    uint32_t len = 0;
    std::string s;
    if (!rdany_3(img, base, &lenw, 8))
        return std::string();
    len = (uint32_t)(lenw & 0xFFFFFFFFULL);
    if (len == 0 || len > 64)
        return std::string();
    if (!rdany_3(img, base + 8, &data, 8) || data == 0)
        return std::string();
    if (len > 7)
        return rstr_3(img, data, (size_t)len + 1);
    s = inl_3(data);
    if (s.size() != len)
        return std::string();
    return s;
}

static std::string probe_3(const Image &img, const char *tag, uint64_t base)
{
    std::string t;
    for (int k = 0; k < 16; k++)
    {
        uint64_t va = base + (uint64_t)k * 8;
        uint64_t v = 0;
        std::string s;
        std::string i;
        std::string sc;
        if (!rdany_3(img, va, &v, 8) || v == 0)
            continue;
        s = rstr_3(img, v, 40);
        if (!s.empty())
            t += out_fmt("- %s+0x%02x `0x%llx`  str \"%s\"\n", tag, k * 8,
                         (unsigned long long)v, s.c_str());
        i = inl_3(v);
        if (!i.empty())
            t += out_fmt("- %s+0x%02x `0x%llx`  inl \"%s\"\n", tag, k * 8,
                         (unsigned long long)v, i.c_str());
        sc = scstr_3(img, va);
        if (!sc.empty())
            t += out_fmt("- %s+0x%02x `0x%llx`  sc \"%s\"\n", tag, k * 8,
                         (unsigned long long)v, sc.c_str());
    }
    return t;
}

void dump_colmap(const Image &img, const Seeds &s)
{
    const uint64_t arr = img.base + 0x1154f08ULL;
    std::string idx;
    std::vector<std::string> bodies;
    for (int i = 0; i < 157; i++)
    {
        uint64_t t = 0;
        uint64_t vt = 0;
        uint64_t ti = 0;
        uint64_t csv = 0;
        uint64_t buckets = 0;
        uint64_t cnt = 0;
        uint64_t rows = 0;
        uint64_t a = 0;
        uint64_t b = 0;
        uint64_t c = 0;
        std::string nm;
        std::string body;
        if (!rdany_3(img, arr + (uint64_t)i * 8, &t, 8) || !t)
            continue;
        rdany_3(img, t, &vt, 8);
        rdany_3(img, t + 0x50, &ti, 8);
        if (!rdany_3(img, t + 0x58, &csv, 8) || !csv)
            continue;
        rdany_3(img, csv, &buckets, 8);
        rdany_3(img, csv + 8, &cnt, 8);
        rdany_3(img, csv + 0x18, &rows, 8);
        if (rdany_3(img, csv + 0x58, &a, 8) && a && rdany_3(img, a + 0x18, &b, 8) && b)
        {
            if (rdany_3(img, b + 0x30, &c, 8))
                nm = scstr_3(img, b + 0x30);
        }
        body = out_fmt("# tbl %d\n\n- table `0x%llx` vtable `0x%llx` idx %llu\n- csv `0x%llx`\n"
                       "- buckets `0x%llx` n=%llu\n- rows `0x%llx`\n- name \"%s\"\n\n",
                       i, (unsigned long long)t, (unsigned long long)vt, (unsigned long long)ti,
                       (unsigned long long)csv, (unsigned long long)buckets, (unsigned long long)cnt,
                        (unsigned long long)rows, nm.c_str());
        body += "\n## probe\n\n";
        if (win_ok_3(t))
            body += probe_3(img, "t", t);
        if (win_ok_3(csv))
            body += probe_3(img, "csv", csv);
        if (win_ok_3(a))
            body += probe_3(img, "a", a);
        if (win_ok_3(b))
            body += probe_3(img, "b", b);
        if (win_ok_3(buckets) && cnt > 0 && cnt <= 4096)
        {
            size_t shown = 0;
            for (uint64_t k = 0; k < cnt && shown < 48; k++)
            {
                uint64_t e = 0;
                if (!rdany_3(img, buckets + k * 8, &e, 8) || !e)
                    continue;
                for (int chain = 0; chain < 8 && shown < 48; chain++)
                {
                    if (!win_ok_3(e))
                        break;
                    body += out_fmt("\n## bucket %llu entry `0x%llx`\n\n", (unsigned long long)k,
                                    (unsigned long long)e);
                    for (int q = 0; q < 6; q++)
                    {
                        uint64_t w = 0;
                        std::string st;
                        if (!rdany_3(img, e + (uint64_t)q * 8, &w, 8))
                            break;
                        st = rstr_3(img, w, 40);
                        body += out_fmt("- `+0x%02x` = `0x%llx`%s%s%s\n", q * 8,
                                        (unsigned long long)w, st.empty() ? "" : "  \"",
                                        st.empty() ? "" : st.c_str(), st.empty() ? "" : "\"");
                    }
                    {
                        std::string en = scstr_3(img, e + 0x10);
                        uint64_t colw = 0;
                        if (!en.empty())
                        {
                            rdany_3(img, e + 0x20, &colw, 8);
                            body += out_fmt("- name \"%s\"  col %llu\n", en.c_str(),
                                            (unsigned long long)(colw & 0xFFFFFFFFULL));
                        }
                    }
                    shown++;
                    {
                        uint64_t nxt = 0;
                        if (!rdany_3(img, e, &nxt, 8) || !nxt || nxt == e)
                            break;
                        e = nxt;
                    }
                }
            }
        }
        bodies.push_back(body);
        idx += out_fmt("- [%d] `0x%llx` n=%llu rows `0x%llx` name \"%s\"\n", i,
                       (unsigned long long)csv, (unsigned long long)cnt, (unsigned long long)rows,
                       nm.c_str());
    }
    std::string all = out_fmt("# column map\n\n- arr: `0x%llx`\n- tables: %zu\n\n## tables\n\n",
                              (unsigned long long)arr, bodies.size());
    all += idx;
    all += "\n";
    for (size_t i = 0; i < bodies.size(); i++)
    {
        all += "\n";
        all += bodies[i];
    }
    out_write("columns", "map-all", all);
    RCL_LOGLN("[dump] column map %zu tables", bodies.size());
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
