#ifndef RCL_DUMP_H
#define RCL_DUMP_H

#include "rcl_scan.h"

namespace rcl
{

void dump_index(const Image &img);
void dump_anchors(const Image &img, const Seeds &s);
void dump_properties(const Image &img, const Seeds &s);
void dump_columns(const Image &img, const Seeds &s);
void dump_colmap(const Image &img, const Seeds &s);
void dump_vtables(const Image &img);
void dump_ctors(const Image &img);
void dump_targets(const Image &img, const Seeds &s);
void dump_missing(const Image &img);

void dump_all(const Image &img, const Seeds &s);

} // namespace rcl

#endif
