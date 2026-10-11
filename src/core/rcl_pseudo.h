#ifndef RCL_PSEUDO_H
#define RCL_PSEUDO_H

#include "rcl_disasm.h"

#include <string>

namespace rcl
{

std::string pseudo_function(const Func &f, uint64_t base, const NameTable &names,
                            const NameTable &fields, const char *title, size_t max_lines);

} // namespace rcl

#endif
