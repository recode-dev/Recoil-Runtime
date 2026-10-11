#include "rcl_dump.h"

#include "rcl_find.h"
#include "rcl_syms.h"
#include "rcl_disasm.h"
#include "rcl_pseudo.h"
#include "rcl_objc.h"
#include "rcl_log.h"
#include "../utils/rcl_out.h"

#include <algorithm>
#include <map>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <vector>

namespace rcl
{

namespace
{

uint64_t cfg_u64(const char *name, uint64_t def)
{
    const char *v = getenv(name);
    if (!v || !*v)
        return def;
    return strtoull(v, nullptr, 0);
}

void parse_rvas(const char *env, std::vector<uint64_t> &out)
{
    if (!env || !*env)
        return;
    const char *p = env;
    while (*p)
    {
        char *end = nullptr;
        const unsigned long long v = strtoull(p, &end, 0);
        if (end == p)
        {
            p++;
            continue;
        }
        if (v > 0x1000 && v < 0x100000000ULL)
            out.push_back((uint64_t)v);
        p = end;
    }
}

std::string fn_name(uint64_t rva)
{
    char b[32];
    snprintf(b, sizeof b, "fn-%06llx", (unsigned long long)rva);
    return std::string(b);
}

void collect_names(const FindResult &fr, NameTable &fns, NameTable &fields)
{
    size_t i = 0;
    for (i = 0; i < fr.items.size(); i++)
    {
        const Found &f = fr.items[i];
        if (!f.value)
            continue;
        if (f.kind == 1)
        {
            fields.add(f.value, f.key);
            continue;
        }
        if (f.value <= 0x1000)
            continue;
        fns.add(f.value, f.key);
    }
    fns.finalize();
    fields.finalize();
}

} // namespace

void dump_index(const Image &img)
{
    std::string t = "# Recoil-Runtime dump\n\n";
    t += out_fmt("- base: `0x%llx`\n", (unsigned long long)img.base);
    t += out_fmt("- image_vmsize: `0x%llx`\n\n", (unsigned long long)img.image_vmsize);
    t += "report: `map-all`\n";
    t += "sections: `anchors`, `disasm`, `objc`, `pseudo`, `map-all`\n";
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

void dump_targets(const Image &img, const Seeds &s)
{
    FindResult fr = find_all(img, s);
    std::string t = out_fmt("# targets\n\n- total: %zu\n- by symbol: %zu\n- by field hint: %zu\n"
                            "- by hint rva (prologue check): %zu\n- unresolved: %zu\n\n",
                            kTargetCount, fr.by_sym, fr.by_field, fr.by_hint, fr.by_str, fr.by_sing,
                            fr.missing);
    size_t i = 0;
    t += "## offsets\n\n```js\nexport const offsets = Object.freeze(\n{\n";
    for (i = 0; i < fr.items.size(); i++)
        t += out_fmt("    %s: 0x%llx,\n", fr.items[i].key, (unsigned long long)fr.items[i].value);
    t += "});\n```\n\n## detail\n\n| key | value | kind | src | symbol / leaf candidates |\n";
    t += "|---|---|---|---|---|\n";
    for (i = 0; i < fr.items.size(); i++)
    {
        const Found &f = fr.items[i];
        t += out_fmt("| `%s` | `0x%llx` | %u | %s | %s |\n", f.key, (unsigned long long)f.value,
                     (unsigned)f.kind, f.src, f.info.empty() ? "-" : f.info.c_str());
    }
    t += "\n## anchor profiles\n\n";
    for (i = 0; i < fr.items.size(); i++)
    {
        const Found &p = fr.items[i];
        if (p.value <= 0x1000 || (strcmp(p.src, "rva+") && strcmp(p.src, "str")))
            continue;
        t += out_fmt("### %s `0x%llx`\n\n", p.key, (unsigned long long)p.value);
        std::string prof;
        code_profile(img, p.value, prof);
        t += prof;
        t += "\n";
    }
    out_write_root("map-all", t);
    RCL_LOGLN("[dump] targets sym %zu field %zu unresolved %zu", fr.by_sym, fr.by_field, fr.missing);
}

void dump_objc(const Image &img)
{
    std::vector<ObjcSymbol> syms;
    const size_t got = objc_collect(img, syms);
    std::sort(syms.begin(), syms.end(),
              [](const ObjcSymbol &a, const ObjcSymbol &b) { return a.rva < b.rva; });
    std::string t = "# objc symbols\n\n";
    t += out_fmt("- classes with methods in image: %zu\n", objc_class_count(syms));
    t += out_fmt("- methods in image: %zu\n\n", got);
    if (!got)
    {
        t += "the objc runtime exposed nothing inside this image\n";
        out_write_root("objc", t);
        return;
    }
    const uint64_t cap = cfg_u64("RCL_OBJC_MAX", 20000);
    t += "| rva | method |\n|---|---|\n";
    size_t i = 0;
    for (i = 0; i < syms.size() && (uint64_t)i < cap; i++)
        t += out_fmt("| `0x%llx` | `%s[%s %s]` |\n", (unsigned long long)syms[i].rva,
                     syms[i].meta ? "+" : "-", syms[i].cls.c_str(), syms[i].sel.c_str());
    if ((uint64_t)i < syms.size())
        t += out_fmt("\n(cut: RCL_OBJC_MAX=%llu of %zu)\n", (unsigned long long)cap, syms.size());
    out_write_root("objc", t);
    RCL_LOGLN("[dump] objc: %zu methods", got);
}

void dump_code(const Image &img, const Seeds &s)
{
    FindResult fr = find_all(img, s);
    NameTable fns;
    NameTable fields;
    std::vector<uint64_t> rvas;
    size_t i = 0;
    const uint64_t maxf = cfg_u64("RCL_DISASM_MAX", 96);
    const uint64_t cap_insns = cfg_u64("RCL_DISASM_INSNS", 2000);
    const uint64_t cap_lines = cfg_u64("RCL_PSEUDO_LINES", 400);

    collect_names(fr, fns, fields);
    for (i = 0; i < fr.items.size(); i++)
    {
        const Found &f = fr.items[i];
        if (f.kind == 1 || !f.value || f.value <= 0x1000)
            continue;
        rvas.push_back(f.value);
    }
    if (rvas.empty())
    {
        RCL_LOGLN("[dump] code: no function targets resolved");
        return;
    }

    {
        std::vector<ObjcSymbol> syms;
        objc_collect(img, syms);
        objc_names(syms, fns);
    }
    parse_rvas(getenv("RCL_DISASM_RVAS"), rvas);
    for (size_t k = 0; k < rvas.size(); k++)
    {
        if (!fns.lookup(rvas[k]))
            fns.add(rvas[k], fn_name(rvas[k]));
    }
    fns.finalize();

    std::map<uint64_t, std::vector<uint64_t>> callers;
    code_callers(img, rvas, callers);

    std::string didx = out_fmt("# disassembly\n\n- functions: %zu\n- instruction cap: %llu\n\n",
                               rvas.size(), (unsigned long long)cap_insns);
    std::string pidx = out_fmt("# pseudocode\n\n- functions: %zu\n- line cap: %llu\n\n",
                               rvas.size(), (unsigned long long)cap_lines);
    size_t written = 0;
    for (i = 0; i < rvas.size(); i++)
    {
        const uint64_t rva = rvas[i];
        Func fn;
        std::string page;
        std::string pre;
        if (!disasm_function(img, img.base + rva, (size_t)cap_insns, fn))
            continue;
        const std::string *nm = fns.lookup(rva);
        const std::string key = nm ? *nm : fn_name(rva);
        pre += out_fmt("# %s `0x%llx`\n\n", key.c_str(), (unsigned long long)rva);
        pre += out_fmt("- insns: %zu\n- end: `0x%llx`\n", fn.size(),
                       (unsigned long long)(fn.end - img.base));
        std::map<uint64_t, std::vector<uint64_t>>::iterator it = callers.find(rva);
        if (it != callers.end() && !it->second.empty())
        {
            pre += out_fmt("- called from: %zu site%s", it->second.size(),
                           it->second.size() == 1 ? "" : "s");
            for (size_t k = 0; k < it->second.size() && k < 12; k++)
                pre += out_fmt(" `0x%llx`", (unsigned long long)it->second[k]);
            if (it->second.size() > 12)
                pre += " ...";
            pre += "\n";
        }
        pre += "\n";

        page = pre + "## disassembly\n\n";
        disasm_listing(fn, img.base, fns, page);
        out_write("disasm", fn_name(rva).c_str(), page);

        out_write("pseudo", fn_name(rva).c_str(),
                  pre + "## pseudocode\n\n" +
                      pseudo_function(fn, img.base, fns, fields, key.c_str(), (size_t)cap_lines));

        didx += out_fmt("- `%s` [`0x%llx`](%s.md) insns %zu\n", key.c_str(), (unsigned long long)rva,
                        fn_name(rva).c_str(), fn.size());
        pidx += out_fmt("- `%s` [`0x%llx`](%s.md) insns %zu\n", key.c_str(), (unsigned long long)rva,
                        fn_name(rva).c_str(), fn.size());
        written++;
        if ((uint64_t)written >= maxf)
            break;
    }
    if (rvas.size() > written)
    {
        didx += out_fmt("\n(cut: RCL_DISASM_MAX=%llu of %zu)\n", (unsigned long long)maxf, rvas.size());
        pidx += out_fmt("\n(cut: RCL_DISASM_MAX=%llu of %zu)\n", (unsigned long long)maxf, rvas.size());
    }
    out_write("disasm", "index", didx);
    out_write("pseudo", "index", pidx);
    RCL_LOGLN("[dump] code: %zu/%zu functions, callers %zu", written, rvas.size(), callers.size());
}

void dump_all(const Image &img, const Seeds &s)
{
    dump_index(img);
    dump_anchors(img, s);
    dump_targets(img, s);
    dump_objc(img);
    dump_code(img, s);
}

} // namespace rcl
