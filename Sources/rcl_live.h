#ifndef RCL_LIVE_H
#define RCL_LIVE_H

#include "rcl_scan.h"

namespace rcl {

void live_dump(const Image &img, const Seeds &s, int snap);
void live_session(const Image &img, const Seeds &s);

}

#endif
