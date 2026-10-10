#pragma once

#include "rcl_scan.h"

#include <vector>

namespace rcl {

struct ClassTable;

bool runtime_trace_install(const Image &img, const std::vector<ClassTable> &tables);

}
