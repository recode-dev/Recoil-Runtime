#ifndef RCL_MACHO_H
#define RCL_MACHO_H

#include "rcl_scan.h"

#include <string>
#include <vector>

namespace rcl {

const uint32_t kLcSegment64 = 0x19u;
const uint32_t kLcSymtab = 0x2u;
const uint32_t kLcUuid = 0x1Bu;
const uint32_t kLcFunctionStarts = 0x26u;
const uint32_t kLcDataInCode = 0x29u;
const uint32_t kLcBuildVersion = 0x32u;
const uint32_t kLcDyldExportsTrie = 0x80000033u;
const uint32_t kLcDyldChainedFixups = 0x80000034u;

const uint16_t kPtrArm64e = 1;
const uint16_t kPtr64 = 2;
const uint16_t kPtr32 = 3;
const uint16_t kPtr32Cache = 4;
const uint16_t kPtr32Firmware = 5;
const uint16_t kPtr64Offset = 6;
const uint16_t kPtrArm64eKernel = 7;
const uint16_t kPtr64KernelCache = 8;
const uint16_t kPtrArm64eUserland = 9;
const uint16_t kPtrArm64eUserland24 = 10;
const uint16_t kPtrArm64eSharedCache = 11;

struct SegFull {
    char name[17];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t nsects;
    uint32_t maxprot;
    uint32_t initprot;
};

struct SecRange {
    char seg[17];
    char sect[17];
    uint64_t start;
    uint64_t end;
    uint32_t flags;
};

struct MachInsight {
    bool ok = false;
    uint64_t slide = 0;
    uint32_t ncmds = 0;
    uint32_t cputype = 0;
    uint32_t cpusubtype = 0;
    uint32_t filetype = 0;
    uint32_t flags = 0;
    uint32_t platform = 0;
    uint32_t minos = 0;
    uint32_t sdk = 0;
    char uuid[40] = {0};
    uint64_t text_vmaddr = 0;
    uint64_t text_vmsize = 0;
    uint64_t text_lo = 0;
    uint64_t text_hi = 0;
    uint64_t image_lo = 0;
    uint64_t image_hi = 0;
    bool has_symtab = false;
    bool has_function_starts = false;
    bool has_data_in_code = false;
    bool has_unwind_info = false;
    bool has_chained_fixups = false;
    bool has_exports_trie = false;
    uint16_t pointer_format = 0;
    uint32_t fixup_page_size = 0;
    bool is_arm64e = false;
    std::vector<SegFull> segs;
    std::vector<SecRange> sections;
};

bool macho_insight(const Image &img, MachInsight &mi);
bool section_range(const MachInsight &mi, const char *sect, const char *seg, uint64_t &lo, uint64_t &hi);
void sections_named(const MachInsight &mi, const char *sect, std::vector<SecRange> &out);
bool fileoff_to_va(const MachInsight &mi, uint64_t fileoff, uint64_t &va);
bool va_inside_image(const MachInsight &mi, uint64_t va);

uint64_t macho_slot_value(const Image &img, const MachInsight &mi, uint64_t raw, int *how);

std::vector<uint32_t> read_function_starts(const Image &img, const MachInsight &mi);
std::vector<SecRange> read_data_in_code(const Image &img, const MachInsight &mi);
std::vector<uint32_t> read_unwind_starts(const Image &img, const MachInsight &mi);
std::string build_version_text(const MachInsight &mi);

struct FnStarts {
    std::vector<uint32_t> v;
    bool exact = false;
    bool from_function_starts = false;
    bool from_unwind = false;
    bool from_scan = false;
    uint32_t scanned_ok = 0;
    uint32_t rejected = 0;
    bool is_start(uint32_t rva) const;
    uint32_t fn_at(uint32_t rva, bool *at_start = nullptr) const;
    uint32_t end_of(uint32_t rva) const;
    uint32_t size_of(uint32_t rva) const;
};

void fn_starts_build(const Image &img, const MachInsight &mi, FnStarts &fs);
bool entry_prologue(uint32_t w);
bool leaf_getter_at(const Image &img, uint32_t rva);
bool in_ranges(const std::vector<SecRange> &r, uint64_t va);

}

#endif
