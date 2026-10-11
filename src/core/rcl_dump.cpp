#include "rcl_dump.h"

#include "rcl_find.h"
#include "rcl_log.h"
#include "../utils/rcl_out.h"

#include <string>
#include <vector>

namespace rcl
{

void dump_index(const Image &img)
{
    std::string t = "# Recoil-Runtime dump\n\n";
    t += out_fmt("- base: `0x%llx`\n", (unsigned long long)img.base);
    t += out_fmt("- image_vmsize: `0x%llx`\n\n", (unsigned long long)img.image_vmsize);
    t += "report: `map-all`\n";
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
    out_write_root("map-all", t);
    RCL_LOGLN("[dump] targets sym %zu field %zu unresolved %zu", fr.by_sym, fr.by_field, fr.missing);
}

void dump_all(const Image &img, const Seeds &s)
{
    dump_index(img);
    dump_anchors(img, s);
    dump_targets(img, s);
}

} // namespace rcl
