#include "rcl_scan.h"
#include <string.h>

namespace rcl {

Seeds Seeds::build69() {
    Seeds s{};
    s.text_off      = 0x4000;
    s.text_end_off  = 0xd8af60;
    s.getbattle_off = 0x8c5130;
    s.propget_off   = 0xafd76c;
    s.colname_off   = 0xbc75e8;
    s.cstr_va       = 0;
    s.cstr_size     = 0;
    return s;
}

bool Image::cstr(uint64_t va, std::string &out) const {
    out.clear();
    for (int i = 0; i < 48; i++) {
        char c = 0;
        if (!read(ctx, va + i, &c, 1)) return false;
        if (c == 0) break;
        if ((unsigned char)c < 32 || (unsigned char)c > 126) return false;
        out.push_back(c);
    }
    return out.size() >= 3;
}

static inline int64_t sign_extend(uint64_t v, int bits) {
    uint64_t m = 1ULL << (bits - 1);
    return (int64_t)((v ^ m) - m);
}

bool branch_target(const Image &img, uint64_t va, uint64_t &target) {
    uint32_t w = 0;
    if (!img.u32(va, w)) return false;
    if ((w & 0xFC000000) == 0x14000000) {
        target = va + ((uint64_t)(sign_extend(w & 0x03FFFFFF, 26)) << 2);
        return true;
    }
    if ((w & 0xFF000010) == 0x54000000) {
        target = va + ((uint64_t)(sign_extend((w >> 5) & 0x7FFFF, 19)) << 2);
        return true;
    }
    if ((w & 0x7E000000) == 0x34000000) {
        target = va + ((uint64_t)(sign_extend((w >> 5) & 0x7FFFF, 19)) << 2);
        return true;
    }
    return false;
}

static bool is_bl_to(const Image &img, uint64_t va, uint64_t target) {
    uint32_t w = 0;
    if (!img.u32(va, w)) return false;
    if ((w & 0xFC000000) != 0x94000000) return false;
    uint64_t t = va + ((uint64_t)(sign_extend(w & 0x03FFFFFF, 26)) << 2);
    return t == target;
}

static bool movz_w1(uint32_t w, uint32_t &imm) {
    if ((w & 0xFFE00000) != 0x52800000) return false;
    if ((w & 0x1F) != 1) return false;
    imm = (w >> 5) & 0xFFFF;
    return true;
}

static bool adrp_at(const Image &img, uint64_t va, uint64_t &page, uint32_t &rd) {
    uint32_t w = 0;
    if (!img.u32(va, w)) return false;
    if ((w & 0x9F000000) != 0x90000000) return false;
    uint64_t imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3);
    page = (va & ~0xFFFULL) + ((uint64_t)sign_extend(imm, 21) << 12);
    rd = w & 0x1F;
    return true;
}

static bool add_imm(const Image &img, uint64_t va, uint32_t rd, uint64_t &res) {
    uint32_t w = 0;
    if (!img.u32(va, w)) return false;
    if ((w & 0x7F000000) != 0x11000000) return false;
    if (((w >> 5) & 0x1F) != rd) return false;
    uint64_t page = 0;
    if (!adrp_at(img, va - 4, page, rd)) return false;
    res = page + ((w >> 10) & 0xFFF);
    return true;
}

static int dest_reg(uint32_t w) {

    if ((w & 0x7F800000) == 0x52800000 || (w & 0x7F800000) == 0x12800000) return w & 0x1F;

    if ((w & 0x3B000000) == 0x39000000 && ((w >> 22) & 1)) return w & 0x1F;
    uint32_t ldu = w & 0xFFE00C00;
    if (ldu == 0x38400000) return w & 0x1F;
    if (ldu == 0xB8400000) return w & 0x1F;
    if (ldu == 0xF8400000) return w & 0x1F;
    uint32_t ldp = w & 0x7FC00000;
    if (ldp == 0x29400000 || ldp == 0xA9400000 || ldp == 0x69400000 || ldp == 0x28C00000) return w & 0x1F;

    if ((w & 0x1F000000) == 0x11000000 && (w & 0x0F000000) != 0x0F000000) return w & 0x1F;
    if ((w & 0x1F200000) == 0x0B000000) return w & 0x1F;

    if ((w & 0x1F200000) == 0x0A000000) return w & 0x1F;
    if ((w & 0x1F800000) == 0x12000000) return w & 0x1F;

    if ((w & 0x1FE00000) == 0x1A800000) return w & 0x1F;

    if ((w & 0xFFE0FFE0) == 0x2A0003E0 || (w & 0xFFE0FFE0) == 0xAA0003E0) return w & 0x1F;

    if ((w & 0x9F000000) == 0x90000000 || (w & 0x9F000000) == 0x10000000) return w & 0x1F;
    return -1;
}

StoreDecoded decode_store_to_w0(const Image &img, uint64_t at, int n) {
    StoreDecoded d;
    for (int k = 0; k < n; k++) {
        uint32_t w = 0;
        if (!img.u32(at + 4 * k, w)) break;
        if ((w & 0xFFC0001F) == 0x39000000) { d = {true, "strb", (int64_t)((w >> 10) & 0xFFF), 1}; return d; }
        if ((w & 0xFFC0001F) == 0xB9000000) { d = {true, "str",  (int64_t)(((w >> 10) & 0xFFF) * 4), 4}; return d; }
        if ((w & 0xFFC0001F) == 0xF9000000) { d = {true, "strx", (int64_t)(((w >> 10) & 0xFFF) * 8), 8}; return d; }
        if ((w & 0xFFE00C1F) == 0x38000000) { d = {true, "sturb", sign_extend((w >> 12) & 0x1FF, 9), 1}; return d; }
        if ((w & 0xFFE00C1F) == 0xB8000000) { d = {true, "stur",  sign_extend((w >> 12) & 0x1FF, 9), 4}; return d; }
        if ((w & 0xFFC00000) == 0x39000000 && (w & 0x1F) == 31) {
            d = {true, "strb_zr", (int64_t)((w >> 10) & 0xFFF), 1}; return d;
        }
        if ((w & 0xFFC00000) == 0x29000000) { d = {true, "stp_w", (int64_t)(((w >> 15) & 0x7F) * 4), 8}; return d; }
    }
    return d;
}

std::vector<PropSite> scan_property_sites(const Image &img, const Seeds &s) {
    std::vector<PropSite> out;
    const uint64_t target = img.base + s.propget_off;
    for (uint64_t va = img.base + s.text_off; va + 4 <= img.base + s.text_end_off; va += 4) {
        if (!is_bl_to(img, va, target)) continue;
        PropSite p{};
        p.site = va;
        p.id = 0;
        for (int k = 1; k <= 4; k++) {
            uint32_t w = 0;
            if (!img.u32(va - 4 * k, w)) break;
            uint32_t imm = 0;
            if (movz_w1(w, imm)) { p.id = imm; break; }
        }
        StoreDecoded d = decode_store_to_w0(img, va + 4, 8);
        if (d.found && d.off >= 0 && d.off < 0x100000) {
            p.field = (uint32_t)d.off;
            p.width = d.width;
            p.kind = d.kind;
            out.push_back(p);
        }
    }
    return out;
}

std::vector<ColumnSite> scan_column_sites(const Image &img, const Seeds &s) {
    std::vector<ColumnSite> out;
    const uint64_t target = img.base + s.colname_off;
    for (uint64_t va = img.base + s.text_off; va + 4 <= img.base + s.text_end_off; va += 4) {
        if (!is_bl_to(img, va, target)) continue;
        std::string name;
        for (int k = 1; k <= 4; k++) {
            uint64_t strva = 0;
            uint32_t rd = 0;
            if (!adrp_at(img, va - 4 * k, strva, rd)) continue;
            uint64_t full = 0;
            if (!add_imm(img, va - 4 * k + 4, rd, full)) continue;
            (void)strva;
            if (img.cstr(full, name)) break;
            name.clear();
        }
        if (name.empty()) continue;

        for (int k = 1; k <= 8; k++) {
            uint32_t w = 0;
            if (!img.u32(va + 4 * k, w)) break;
            bool isStr = ((w & 0xFFC00000) == 0xB9000000 && (w & 0x1F) == 0);
            bool isStur = ((w & 0xFFE00C00) == 0xB8000000 && (w & 0x1F) == 0);
            if (!isStr && !isStur) continue;
            uint32_t imm = isStr ? ((w >> 10) & 0xFFF) : (uint32_t)sign_extend((w >> 12) & 0x1FF, 9);
            uint32_t base = (w >> 5) & 0x1F;
            uint64_t slot_va = 0;
            for (int b = 1; b <= 8; b++) {
                uint64_t page = 0;
                uint32_t rd = 0;
                if (!adrp_at(img, va + 4 * k - 4 * b, page, rd)) continue;
                if (rd == base) { slot_va = page + imm; break; }
            }
            out.push_back({name, imm, va, slot_va});
            break;
        }
    }
    return out;
}

std::vector<OwnFlag> scan_own_char_flags(const Image &img, const Seeds &s) {
    std::vector<OwnFlag> out;
    const uint64_t target = img.base + s.getbattle_off;
    for (uint64_t va = img.base + s.text_off; va + 4 <= img.base + s.text_end_off; va += 4) {
        if (!is_bl_to(img, va, target)) continue;

        int R = -1, defK = -1;
        for (int k = 1; k <= 6; k++) {
            uint32_t w = 0;
            if (!img.u32(va + 4 * k, w)) break;
            if ((w & 0xFFC00000) == 0xF9400000 && ((w >> 5) & 0x1F) == 0 &&
                ((w >> 10) & 0xFFF) * 8 == 0x28) {
                R = w & 0x1F;
                defK = k;
                break;
            }
        }
        if (R < 0) continue;

        for (int k = defK + 1; k <= defK + 64; k++) {
            uint64_t a = va + 4 * k;
            uint32_t w = 0;
            if (!img.u32(a, w)) break;
            int dr = dest_reg(w);
            if (dr == R) break;
            if ((w & 0xFFC00000) == 0x39400000 && (int)((w >> 5) & 0x1F) == R) {
                out.push_back({(uint32_t)((w >> 10) & 0xFFF), 0, "ldrb"});
            } else if ((w & 0xFFC00000) == 0x79400000 && (int)((w >> 5) & 0x1F) == R) {
                out.push_back({(uint32_t)(((w >> 10) & 0xFFF) * 2), 0, "ldrh"});
            }
        }
    }
    return out;
}

}
