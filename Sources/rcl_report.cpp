#include "rcl_report.h"
#include "rcl_log.h"
#include "rcl_classdump.h"
#include "rcl_docgen.h"
#include "rcl_hook.h"
#include <stdlib.h>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace rcl
{

static void dump_property_sites(const Image &img, const Seeds &s)
{
    auto sites = scan_property_sites(img, s);
    std::map<uint32_t, std::set<uint32_t>> byField;
    for (auto &p : sites)
        byField[p.field].insert(p.id);

    RCL_LOGLN("[property sites] sites=%zu  unique(field)=%zu", sites.size(), byField.size());
    RCL_LOGLN("   field -> the property ids written into it");
    for (auto &kv : byField)
    {
        RCL_LOG("   +0x%04x <-", kv.first);
        for (auto id : kv.second)
            RCL_LOG(" 0x%02x", id);
        RCL_LOGLN("");
    }
}

static void dump_column_names(const Image &img, const std::vector<ColumnSite> &cols)
{
    std::map<uint64_t, std::string> byPageOff;
    for (auto &c : cols)
        if (c.slot_va)
            byPageOff[c.slot_va] = c.name;

    RCL_LOGLN("[column names] sites=%zu  unique=%zu", cols.size(), byPageOff.size());
    RCL_LOGLN("   name and the address it was loaded from (the schema's own strings)");
    const char *mx = getenv("RCL_COLNAMES_MAX");
    const int maxn = (mx && *mx) ? atoi(mx) : 0;
    int shown = 0;
    for (auto &kv : byPageOff)
    {
        RCL_LOGLN("   rva 0x%06x  \"%s\"", (unsigned)(kv.first - img.base), kv.second.c_str());
        if (maxn > 0 && ++shown >= maxn)
        {
            RCL_LOGLN("   ... (%zu total, first %d shown; RCL_COLNAMES_MAX=0 for all)",
                      byPageOff.size(), maxn);
            break;
        }
    }
    RCL_LOGLN("   -- names mentioning charge / hyper, listed in full --");
    for (auto &kv : byPageOff)
    {
        const std::string &nm = kv.second;
        if (nm.find("vercharge") == std::string::npos && nm.find("yper") == std::string::npos &&
            nm.find("Charge") == std::string::npos)
            continue;
        RCL_LOGLN("   rva 0x%06x  \"%s\"", (unsigned)(kv.first - img.base), nm.c_str());
    }
}

static void dump_own_char_flags(const Image &img, const Seeds &s)
{
    auto flags = scan_own_char_flags(img, s);
    std::set<uint32_t> uniq;
    for (auto &f : flags)
        uniq.insert(f.off);
    RCL_LOGLN("[own-character byte flags] hits=%zu  unique offsets=%zu", flags.size(), uniq.size());
    for (auto o : uniq)
        RCL_LOGLN("   +0x%04x", o);
}

static void dump_class_columns(const Image &img, const Seeds &s)
{
    const std::vector<ClassBoundary> bounds = discover_class_boundaries(img);
    std::vector<ClassColumns> cls = scan_class_columns(img, s, bounds);
    size_t total = 0, mism = 0, unresolved_classes = 0;
    for (auto &c : cls)
        total += c.items.size();
    RCL_LOGLN("[class columns] classes=%zu  columns=%zu  (all columns of every data class, live)",
              cls.size(), total);
    for (auto &c : cls)
    {
        bool all_zero = !c.items.empty();
        for (auto &it : c.items)
            if (it.id)
                all_zero = false;
        if (c.items.size() != c.cols)
            mism++;
        if (all_zero)
            unresolved_classes++;
        const char *nm = c.name ? c.name : "?";
        RCL_LOGLN("  %-30s loader=0x%06x  cols=%3zu/%u%s%s", nm, c.start, c.items.size(), c.cols,
                  c.items.size() == c.cols ? "" : "  MISMATCH",
                  all_zero ? "  ids not resolved yet" : "");
        RCL_LOG("     ");
        int n = 0;
        for (auto &it : c.items)
        {
            if (it.id == 0xFFFFFFFFu)
                RCL_LOG("%s%s=?", n ? " " : "", it.name.c_str());
            else
                RCL_LOG("%s%s=%u", n ? " " : "", it.name.c_str(), it.id);
            if (++n % 8 == 0)
            {
                RCL_LOGLN("");
                RCL_LOG("     ");
            }
        }
        RCL_LOGLN("");
    }
    if (mism || unresolved_classes)
        RCL_LOGLN("[class columns] mismatched=%zu  not-yet-resolved=%zu", mism, unresolved_classes);
}

void report_run(const Image &img, const Seeds &s)
{
    RCL_LOGLN("== Recoil-Runtime offset search ==");
    RCL_LOGLN("image base 0x%llx  vmsize 0x%llx", (unsigned long long)img.base,
              (unsigned long long)img.vmsize);
    RCL_LOGLN("__text     0x%llx..0x%llx", (unsigned long long)s.text_off,
              (unsigned long long)s.text_end_off);
    RCL_LOGLN("mode: read-only scan, no hooks installed");
    RCL_LOGLN("");

    std::vector<ColumnSite> cols = scan_column_sites(img, s);

    dump_property_sites(img, s);
    RCL_LOGLN("");
    dump_column_names(img, cols);
    RCL_LOGLN("");
    dump_own_char_flags(img, s);
    RCL_LOGLN("");
    dump_class_tree(img);
    RCL_LOGLN("");
    {
        const char *e = getenv("RCL_CLASS_COLUMNS");
        if (!e || *e != '0')
            dump_class_columns(img, s);
        RCL_LOGLN("");
    }
    ScanStats ss;
    std::vector<ClassTable> tb = scan_class_tables(img, &ss);
    symbolize_tables(img, tb);
    runtime_trace_install(img, tb);
    write_class_docs(img);
    RCL_LOGLN("");
    write_symbols(img, tb, dumps_root());
    RCL_LOGLN("");
    write_all_bundle();
    RCL_LOGLN("");
    RCL_LOGLN("== end ==");
}

} // namespace rcl
