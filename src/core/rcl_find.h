#ifndef RCL_FIND_H
#define RCL_FIND_H

#include "rcl_scan.h"
#include <stddef.h>
#include <stdint.h>

namespace rcl
{

struct Target
{
    const char *key;
    uint8_t kind;
    const char *cls;
    uint64_t seed;
};

extern const Target kTargets[];
extern const size_t kTargetCount;

struct Found
{
    const char *key;
    const char *alias_of;
    uint64_t value;
    uint8_t kind;
    const char *src;
    std::string info;
};

struct FindResult
{
    size_t resolved = 0;
    size_t duplicated = 0;
    size_t ambiguous = 0;
    size_t missing = 0;
    size_t by_sym = 0;
    size_t by_field = 0;
    std::vector<Found> items;
};

FindResult find_all(const Image &img, const Seeds &s);

} // namespace rcl

#endif
