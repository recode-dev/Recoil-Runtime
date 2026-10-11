#ifndef RCL_SYMS_H
#define RCL_SYMS_H

#include "rcl_scan.h"

#include <string>
#include <vector>

namespace rcl
{

struct Sym
{
    uint64_t rva = 0;
    uint32_t size = 0;
    std::string name;
};

uint32_t load_symbols(const Image &img, std::vector<Sym> &out);
void norm_key(const char *in, std::string &out);
int64_t sym_match(const std::vector<Sym> &syms, const std::vector<std::string> &norm, const char *key);

} // namespace rcl

#endif
