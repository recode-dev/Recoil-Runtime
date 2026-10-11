#ifndef RCL_DUMP_H
#define RCL_DUMP_H

#include "rcl_scan.h"

namespace rcl
{

void dump_index(const Image &img);
void dump_anchors(const Image &img, const Seeds &s);
void dump_targets(const Image &img, const Seeds &s);
void dump_code(const Image &img, const Seeds &s);
void dump_objc(const Image &img);

void dump_all(const Image &img, const Seeds &s);

} // namespace rcl

#endif
