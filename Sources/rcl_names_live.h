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
    NL_ASSET = 5,
    NL_METHOD_NAMES = 6,
    NL_OVERLAY = 7,
    NL_SLOTSET = 8,
    NL_STRUCT = 9,
    NL_SRC_MAX = NL_STRUCT
};

typedef bool (*NlReadFn)(void *ctx, uint64_t va, void *dst, size_t n);

void nl_init(NlReadFn fn, void *ctx, uint64_t img_lo, uint64_t img_hi);

void nl_observe(uint32_t vt, const char *const *strs, uint32_t n);

const char *nl_label(uint32_t vt, const uint32_t *slots, uint32_t nslots, char *buf, size_t cap,
                     uint32_t *src);

void nl_stats(uint32_t hits[NL_SRC_MAX + 1]);

void nl_add_name(uint32_t rva, const char *label, bool is_vt);

bool nl_load_names_file(const char *path);

const char *nl_match_slots(const uint32_t *slots, uint32_t nslots, char *buf, size_t cap,
                           uint32_t *score, uint32_t *cls_out);

const char *nl_structural(const uint32_t *slots, uint32_t nslots, char *buf, size_t cap,
                          uint32_t *score);

uint32_t nl_build_check(uint32_t *classes, uint32_t *rvas, uint32_t *in_image);

uint32_t nl_doc_count(void);

uint32_t nl_doc_vt_slots(uint32_t cls);

const char *nl_doc_name(uint32_t cls);

enum NlKind
{
    NLK_UNKNOWN = 0,
    NLK_LOGIC = 1,
    NLK_UI = 2,
    NLK_ASSET = 3,
    NLK_AUDIO = 4,
    NLK_KIND_MAX = NLK_AUDIO
};

uint32_t nl_kind(uint32_t vt);

const char *nl_kind_name(uint32_t kind);

} // namespace rcl
