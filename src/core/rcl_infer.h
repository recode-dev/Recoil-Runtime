#ifndef RCL_INFER_H
#define RCL_INFER_H

#include "rcl_disasm.h"
#include "rcl_scan.h"

#include <stdint.h>
#include <string>
#include <vector>

namespace rcl
{

struct InferredName
{
    uint64_t rva = 0;
    std::string name;
    std::string evidence;
};

size_t infer_load_dict(const char *path, std::vector<std::string> &out);
const std::vector<InferredName> &infer_cached(const Image &img, const Seeds &s);
void infer_names(const std::vector<InferredName> &in, NameTable &names);

} // namespace rcl

#endif
