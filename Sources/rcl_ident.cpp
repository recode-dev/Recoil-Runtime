#include "rcl_ident.h"
#include "rcl_log.h"

namespace rcl {

uint32_t crc32_update(uint32_t c, const uint8_t *p, size_t n) {
    static uint32_t tab[256];
    static bool ready = false;
    if (!ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t v = i;
            for (int k = 0; k < 8; k++) v = (v & 1u) ? (0xEDB88320u ^ (v >> 1)) : (v >> 1);
            tab[i] = v;
        }
        ready = true;
    }
    for (size_t i = 0; i < n; i++) c = tab[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
    return c;
}

Stamp text_stamp(const Image &img) {
    Stamp s;
    if (!img.ok()) return s;

    uint8_t hdr[32];
    if (!img.read || !img.read(img.ctx, img.base, hdr, sizeof hdr)) return s;
    const uint32_t magic = *(const uint32_t *)hdr;
    if (magic != 0xFEEDFACFu) return s;
    const uint32_t cputype = *(const uint32_t *)(hdr + 4);
    if ((cputype & 0x00FFFFFFu) != 12u) {
        RCL_LOGLN("[ident] cputype 0x%08x is not arm64", cputype);
        return s;
    }
    s.probes_ok = true;

    uint64_t lo = 0, hi = 0;
    if (!macho_text_range(img, lo, hi)) {
        lo = img.base;
        hi = img.base + (img.vmsize ? img.vmsize : img.image_vmsize);
    }
    if (hi > lo) {
        uint32_t c = 0xFFFFFFFFu;
        uint8_t buf[8192];
        for (uint64_t off = 0; lo + off < hi; ) {
            uint64_t left = hi - (lo + off);
            size_t n = (size_t)(left < (uint64_t)sizeof buf ? left : (uint64_t)sizeof buf);
            if (!img.read(img.ctx, lo + off, buf, n)) break;
            c = crc32_update(c, buf, n);
            off += (uint64_t)n;
        }
        s.crc = c ^ 0xFFFFFFFFu;
    }
    s.valid = true;
    return s;
}

}
