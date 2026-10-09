#include "rcl_report.h"
#include "rcl_log.h"
#include <map>
#include <set>
#include <string>
#include <vector>

namespace rcl {

static void dump_property_sites(const Image &img, const Seeds &s) {
    auto sites = scan_property_sites(img, s);
    std::map<uint32_t, std::set<uint32_t>> byField;
    for (auto &p : sites) byField[p.field].insert(p.id);

    RCL_LOGLN("[property sites] sites=%zu  unique(field)=%zu", sites.size(), byField.size());
    RCL_LOGLN("   field -> the property ids written into it");
    for (auto &kv : byField) {
        RCL_LOG("   +0x%04x <-", kv.first);
        for (auto id : kv.second) RCL_LOG(" 0x%02x", id);
        RCL_LOGLN("");
    }
}

static void dump_column_names(const std::vector<ColumnSite> &cols) {
    std::map<uint64_t, std::string> byPageOff;
    for (auto &c : cols) if (c.slot_va) byPageOff[c.slot_va] = c.name;

    RCL_LOGLN("[column names] sites=%zu  unique=%zu", cols.size(), byPageOff.size());
    RCL_LOGLN("   name and the address it was loaded from (the schema's own strings)");
    int shown = 0;
    for (auto &kv : byPageOff) {
        RCL_LOGLN("   0x%llx  \"%s\"", (unsigned long long)(kv.first - 0x100000000ULL), kv.second.c_str());
        if (++shown >= 32) { RCL_LOGLN("   ... (%zu total, first 32 shown)", byPageOff.size()); break; }
    }
    RCL_LOGLN("   -- names mentioning charge / hyper, listed in full --");
    for (auto &kv : byPageOff) {
        const std::string &nm = kv.second;
        if (nm.find("vercharge") == std::string::npos && nm.find("yper") == std::string::npos &&
            nm.find("Charge") == std::string::npos) continue;
        RCL_LOGLN("   0x%llx  \"%s\"", (unsigned long long)(kv.first - 0x100000000ULL), nm.c_str());
    }
}

static void dump_own_char_flags(const Image &img, const Seeds &s) {
    auto flags = scan_own_char_flags(img, s);
    std::set<uint32_t> uniq;
    for (auto &f : flags) uniq.insert(f.off);
    RCL_LOGLN("[own-character byte flags] hits=%zu  unique offsets=%zu", flags.size(), uniq.size());
    for (auto o : uniq) RCL_LOGLN("   +0x%04x", o);
}

void report_run(const Image &img, const Seeds &s) {
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
    dump_column_names(cols);
    RCL_LOGLN("");
    dump_own_char_flags(img, s);
    RCL_LOGLN("");
    RCL_LOGLN("== end ==");
}

}
