#pragma once

#include <stdint.h>
#include <stddef.h>

namespace rcl
{

enum NlSource
{
    NL_NONE = 0,
    NL_DOC_VT = 1,
    NL_INSTANCE = 2,
    NL_DOC_METHODS = 3,
    NL_STRINGS = 4,
    NL_METHOD_NAMES = 5,
    NL_SRC_MAX = NL_METHOD_NAMES
};

typedef bool (*NlReadFn)(void *ctx, uint64_t va, void *dst, size_t n);

void nl_init(NlReadFn fn, void *ctx, uint64_t img_lo, uint64_t img_hi);

void nl_observe(uint32_t vt, const char *const *strs, uint32_t n);

const char *nl_label(uint32_t vt, const uint32_t *slots, uint32_t nslots, char *buf, size_t cap,
                     uint32_t *src);

void nl_stats(uint32_t hits[NL_SRC_MAX + 1]);

} // namespace rcl
