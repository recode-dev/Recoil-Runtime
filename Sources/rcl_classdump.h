#pragma once

#include "rcl_scan.h"

#include <vector>

namespace rcl {

struct ClassTable {
    uint32_t start = 0;
    uint32_t slots = 0;
    uint32_t named = 0;
    const char *seg = "";
    const char *name = "";
};

std::vector<ClassTable> scan_class_tables(const Image &img);
void dump_class_tree(const Image &img);

}
