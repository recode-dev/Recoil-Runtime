#ifndef RCL_OUT_H
#define RCL_OUT_H

#include <stdarg.h>
#include <stddef.h>
#include <string>

namespace rcl
{

void out_begin(const char *dir);
std::string out_root();
bool out_write(const char *section, const char *name, const std::string &text);
bool out_write_root(const char *name, const std::string &text);
std::string out_fmt(const char *fmt, ...);

} // namespace rcl

#endif
