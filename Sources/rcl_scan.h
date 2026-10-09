// rcl_scan.h - portable AArch64 scanner for runtime offset discovery.
//
// Deliberately free of ObjC/Foundation so the exact same translation unit builds for the device
// (Theos) and for a host test that runs it over the real Mach-O image. That is what makes the
// scanner verifiable off-device.
//
// Everything works off a byte reader, so the device can hand it live memory and the host can hand
// it the mapped file.

#ifndef RCL_SCAN_H
#define RCL_SCAN_H

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <vector>

namespace rcl {

// ---------- seeds ----------
// Build-69 seeds. These are starting points, not the answer: the scanner derives everything else.
struct Seeds {
    uint64_t text_off;        // start of __TEXT.__text, as an offset from the image base
    uint64_t text_end_off;    // end of __TEXT.__text
    uint64_t getbattle_off;   // 0x8c5130  RCL_GETBATTLE_RVA
    uint64_t propget_off;     // 0xafd76c  property-value getter
    uint64_t colname_off;     // 0xbc75e8  column-index-by-name
    uint64_t cstr_va;         // VA of __TEXT.__cstring (for name reads), 0 if unknown
    uint64_t cstr_size;

    static Seeds build69();
};

// ---------- memory access ----------
struct Image {
    uint64_t base = 0;                 // VM base (0x100000000 for the build-69 image)
    uint64_t vmsize = 0;
    void *ctx = nullptr;
    // Read n bytes from VA. Return false if out of range. Never throws.
    bool (*read)(void *ctx, uint64_t va, void *dst, size_t n) = nullptr;

    bool ok() const { return base != 0 && read != nullptr; }
    bool u32(uint64_t va, uint32_t &out) const {
        return read && read(ctx, va, &out, 4);
    }
    // Read a NUL-terminated printable string, max 48 chars.
    bool cstr(uint64_t va, std::string &out) const;
};

// ---------- results ----------

// A `mov w1,#id ; bl <propget> ; str/strb w0,[xN,#field]` site.
struct PropSite {
    uint32_t id = 0;          // property id passed in w1
    uint32_t field = 0;       // destination field offset
    uint8_t width = 0;        // 1 or 4
    uint64_t site = 0;        // VA of the bl
    uint8_t dst_reg = 0;      // xN of the destination
    const char *kind = "";    // "strb" / "str" / ...
    bool id_from_movz = true; // false -> w1 came from somewhere else, treat as soft
};

// A `adrp+add "Name" ; bl <colname> ; str w0,[xN,#slot]` site.
struct ColumnSite {
    std::string name;
    uint32_t slot = 0;
    uint64_t site = 0;
    uint64_t slot_va = 0;   // absolute VA of the cache slot: on device this holds the column index
};

// A byte load on the object reached as [<getbattle>()+0x28] (the own character).
struct OwnFlag {
    uint32_t off = 0;
    uint64_t fn = 0;          // enclosing function start (approximate)
    const char *kind = "";
};

// ---------- the decode primitive ----------
// Decode the first store-to-W0 among `n` instructions given as a word getter.
// Mirrors agent/arm64_decode.js, which is unit-tested against this same image.
struct StoreDecoded {
    bool found = false;
    const char *kind = "";
    int64_t off = 0;
    uint8_t width = 0;
};
StoreDecoded decode_store_to_w0(const Image &img, uint64_t at, int n = 8);

// ---------- scanners ----------
std::vector<PropSite> scan_property_sites(const Image &img, const Seeds &s);
std::vector<ColumnSite> scan_column_sites(const Image &img, const Seeds &s);
std::vector<OwnFlag> scan_own_char_flags(const Image &img, const Seeds &s);

// Move displacement of a b/bl at va, or INT64_MIN if not a branch.
bool branch_target(const Image &img, uint64_t va, uint64_t &target);

} // namespace rcl

#endif // RCL_SCAN_H
