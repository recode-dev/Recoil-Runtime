#ifndef RCL_SCAN_H
#define RCL_SCAN_H

#if __cplusplus < 201703L
#error "Recoil-Runtime needs C++17: -std=c++17 is missing from the build flags"
#endif

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>

namespace rcl {

struct Seeds {
    uint64_t text_off;
    uint64_t text_end_off;
    uint64_t getbattle_off;
    uint64_t propget_off;
    uint64_t colname_off;
    uint64_t cstr_va;
    uint64_t cstr_size;

    static Seeds build69();
};

uint64_t macho_image_size(const void *macho_header);

struct Image {
    uint64_t base = 0;
    uint64_t vmsize = 0;
    uint64_t image_vmsize = 0;
    void *ctx = nullptr;

    bool (*read)(void *ctx, uint64_t va, void *dst, size_t n) = nullptr;

    bool ok() const { return base != 0 && read != nullptr; }
    bool u32(uint64_t va, uint32_t &out) const {
        return read && read(ctx, va, &out, 4);
    }

    bool cstr(uint64_t va, std::string &out) const;
};

struct PropSite {
    uint32_t id = 0;
    uint32_t field = 0;
    uint8_t width = 0;
    uint64_t site = 0;
    uint8_t dst_reg = 0;
    const char *kind = "";
    bool id_from_movz = true;
};

struct ColumnSite {
    std::string name;
    uint32_t slot = 0;
    uint64_t site = 0;
    uint64_t slot_va = 0;
};

struct OwnFlag {
    uint32_t off = 0;
    uint64_t fn = 0;
    const char *kind = "";
};

struct StoreDecoded {
    bool found = false;
    const char *kind = "";
    int64_t off = 0;
    uint8_t width = 0;
};
StoreDecoded decode_store_to_w0(const Image &img, uint64_t at, int n = 8);

std::vector<PropSite> scan_property_sites(const Image &img, const Seeds &s);
std::vector<ColumnSite> scan_column_sites(const Image &img, const Seeds &s);
std::vector<OwnFlag> scan_own_char_flags(const Image &img, const Seeds &s);

bool branch_target(const Image &img, uint64_t va, uint64_t &target);

}

#endif
