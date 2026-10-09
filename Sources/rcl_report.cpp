// rcl_report.cpp - the offset search report.
//
// READ-ONLY. This file never writes to the target process: no inline hooks, no code patching, no
// pointer rewiring. It scans and writes a log. That is the whole contract, and it is what makes the
// dylib safe to drop into LiveContainer.
//
// Portable: the device and the host run exactly this, so the host output is the device output.
//
// What is reported, and how far each item is trusted:
//   [property sites]      solid. The id is a literal in the caller (`mov w1,#id` right before the
//                         call) and the field is the store immediately after the call returns; the
//                         store decode is the same code verified against hand-checked sites.
//   [column names]        solid as a NAME LIST - the strings really are the data schema's column
//                         names. The page+offset shown locates the string, nothing more.
//   [own-character flags] solid, register-liveness checked.
//   [reachability]        solid, byte-compared against the real image.
//
//   NOT reported, because it was tried and did not hold up: the link from a column NAME to a
//   property ID. Reading the 4 bytes at the candidate cache slot looked promising on a few names
//   and turned out to be wrong - 1482 of 2143 slots hold "unset" and the rest 0 or unrelated data,
//   so the store after the name lookup does not belong to the cache. Naming a field therefore still
//   needs the data schema itself, or a different hook point. Do not resurrect this without a
//   runtime check.

#include "rcl_report.h"
#include "rcl_hook.h"
#include "rcl_log.h"
#include <map>
#include <set>
#include <string>
#include <vector>

namespace rcl {

static void dump_property_sites(const Image &img, const Seeds &s) {
    auto sites = scan_property_sites(img, s);
    std::map<uint32_t, std::set<uint32_t>> byField;      // field -> {ids}
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

static void dump_reachability(const Image &img, const Seeds &s) {
    RCL_LOGLN("[reachability] pointer slots holding each seed (informational - nothing is hooked)");
    struct { const char *nm; uint64_t off; } seeds[] = {
        {"getBattle 0x8c5130", s.getbattle_off},
        {"propget   0xafd76c", s.propget_off},
        {"colname   0xbc75e8", s.colname_off},
        {"vt99      0x7a03a0", 0x7a03a0},
    };
    for (auto &sd : seeds) {
        std::vector<uint64_t> slots;
        int n = hook_scan(img, img.base + sd.off, img.base + s.text_off,
                          img.base + s.text_end_off, slots);
        RCL_LOG("   %s -> %d slot(s)", sd.nm, n);
        for (int i = 0; i < n && i < 4; i++)
            RCL_LOG("  0x%llx", (unsigned long long)(slots[i] - img.base));
        RCL_LOGLN("");
    }
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
    dump_reachability(img, s);
    RCL_LOGLN("== end ==");
}

} // namespace rcl
