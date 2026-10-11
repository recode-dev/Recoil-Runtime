#ifndef RCL_OBJC_H
#define RCL_OBJC_H

#include "rcl_disasm.h"

#include <stdint.h>
#include <string>
#include <vector>

namespace rcl
{

struct ObjcSymbol
{
    uint64_t rva = 0;
    std::string cls;
    std::string sel;
    bool meta = false;
};

size_t objc_collect(const Image &img, std::vector<ObjcSymbol> &out);
void objc_names(const std::vector<ObjcSymbol> &in, NameTable &names);
size_t objc_class_count(const std::vector<ObjcSymbol> &in);

} // namespace rcl

#endif
