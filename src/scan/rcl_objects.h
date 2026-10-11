#ifndef RCL_OBJECTS_H
#define RCL_OBJECTS_H

#include "../core/rcl_scan.h"

#include <set>
#include <string>
#include <vector>

namespace rcl
{

struct VTable
{
    uint64_t addr = 0;
    uint32_t slots = 0;
    uint64_t first = 0;
    std::string guess;
};

struct Ctor
{
    uint64_t fn = 0;
    uint64_t vtable = 0;
    uint64_t store_at = 0;
};

struct Leaf
{
    uint64_t fn = 0;
    uint32_t off = 0;
    uint8_t width = 4;
    bool load_x0 = false;
};

std::vector<VTable> scan_vtables(const Image &img);
std::vector<Ctor> scan_ctors(const Image &img, const std::set<uint64_t> &vtables);
std::string vtable_name(const Image &img, uint64_t vtable);
std::vector<Leaf> scan_leaf_getters(const Image &img);

} // namespace rcl

#endif
