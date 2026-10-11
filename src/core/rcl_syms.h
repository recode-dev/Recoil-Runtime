#ifndef RCL_SYMS_H
#define RCL_SYMS_H

#include "rcl_scan.h"

#include <map>
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

struct Found;

uint32_t load_symbols(const Image &img, std::vector<Sym> &out);
void norm_key(const char *in, std::string &out);
int64_t sym_match(const std::vector<Sym> &syms, const std::vector<std::string> &norm, const char *key);

bool code_text_range(const Image &img, uint64_t &lo, uint64_t &hi);
uint64_t code_fn_start(const Image &img, uint64_t va, uint64_t lo);
uint64_t code_str_lookup(const Image &img, uint64_t cstr_va, uint64_t cstr_size, const char *needle, uint32_t *hits);
void code_str_refs(const Image &img, uint64_t cstr_va, uint64_t cstr_size,
                   std::map<uint64_t, std::vector<uint64_t>> &out);
void code_singletons(const Image &img, std::vector<uint64_t> &out);
void code_resolve(const Image &img, const Seeds &s, Found &f, size_t &by_str, size_t &by_sing);

} // namespace rcl

#endif
