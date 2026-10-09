// rcl_report.h
#ifndef RCL_REPORT_H
#define RCL_REPORT_H

#include "rcl_scan.h"

namespace rcl {

// Run every scanner against `img` and write the report to the log. Identical on device and host.
void report_run(const Image &img, const Seeds &s);

} // namespace rcl

#endif
