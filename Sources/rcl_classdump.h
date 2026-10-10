#pragma once

#include "rcl_scan.h"

#include <vector>

namespace rcl {

struct ClassTable {
    uint32_t start = 0;
    uint32_t slots = 0;
    uint32_t named = 0;
    std::string seg;
    const char *name = "";
};

struct SegInfo {
    char name[17];
    uint64_t start;
    uint64_t end;
};

struct ScanStats {
    int hdr_ok = 0;
    uint32_t magic = 0;
    uint32_t ncmds = 0;
    uint64_t slide = 0;
    uint64_t words = 0;
    uint64_t ptr_ok = 0;
    uint64_t entry_ok = 0;
    uint64_t entry_rej = 0;
    uint32_t tables_strict = 0;
    uint32_t tables_loose = 0;
    uint64_t loose_words = 0;
    uint32_t sample_raw = 0;
    uint32_t sample_rva = 0;
    int sample_reason = 0;
    std::vector<SegInfo> segs;
};

std::vector<ClassTable> scan_class_tables(const Image &img, ScanStats *st = nullptr);
void dump_class_tree(const Image &img);
void write_class_docs(const Image &img);
void write_all_bundle();
const char *dumps_root();
void live_docs_note(const Image &img, uint32_t state, int tick);
void live_docs_flush(const Image &img);

}
