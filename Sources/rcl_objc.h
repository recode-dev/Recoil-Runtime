#pragma once

#include <stdint.h>
#include <stdio.h>

namespace rcl
{

void objc_dump(FILE *f, uint64_t base, uint64_t vmsize);

} // namespace rcl
