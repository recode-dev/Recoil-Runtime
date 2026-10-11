#include "rcl_disasm.h"
#include "rcl_syms.h"
#include "rcl_log.h"

#include <algorithm>
#include <set>
#include <stdio.h>
#include <string.h>

namespace rcl
{

namespace
{

const char *kCond[16] = {"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                         "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"};
const char *kShift[4] = {"lsl", "lsr", "asr", "ror"};
const char *kExt[8] = {"uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"};

int64_t sext(uint64_t v, int bits)
{
    const uint64_t m = 1ULL << (bits - 1);
    return (int64_t)((v ^ m) - m);
}

std::string r_x(int r, bool sf, bool sp_ok)
{
    char b[16];
    if (r == 31)
        snprintf(b, sizeof b, "%s", sp_ok ? (sf ? "sp" : "wsp") : (sf ? "xzr" : "wzr"));
    else
        snprintf(b, sizeof b, "%s%d", sf ? "x" : "w", r);
    return std::string(b);
}

std::string r_v(int r, int bytes)
{
    char b[16];
    const char *p = bytes == 16 ? "q" : bytes == 8 ? "d" : bytes == 4 ? "s" : bytes == 2 ? "h" : "b";
    snprintf(b, sizeof b, "%s%d", p, r);
    return std::string(b);
}

std::string hex64(uint64_t v)
{
    char b[32];
    snprintf(b, sizeof b, "0x%llx", (unsigned long long)v);
    return std::string(b);
}

std::string hex_off(int64_t v)
{
    char b[40];
    if (v < 0)
        snprintf(b, sizeof b, "-0x%llx", (unsigned long long)(-v));
    else
        snprintf(b, sizeof b, "0x%llx", (unsigned long long)v);
    return std::string(b);
}

bool decode_bitmask(bool sf, uint32_t n, uint32_t immr, uint32_t imms, uint64_t &out)
{
    uint32_t len = 0;
    uint64_t welem = 0;
    uint64_t val = 0;
    uint64_t esize = 0;
    uint64_t s = 0;
    uint64_t r = 0;
    const uint32_t combined = (n << 6) | ((~imms) & 0x3Fu);
    if (!sf && n)
        return false;
    for (int i = 6; i >= 0; i--)
    {
        if (combined & (1u << i))
        {
            len = (uint32_t)i;
            break;
        }
    }
    if (len < 1 || (len > 5 && !sf) || len > 6)
        return false;
    esize = 1ULL << len;
    s = imms & (esize - 1);
    r = immr & (esize - 1);
    if (s == esize - 1)
        return false;
    welem = (~0ULL >> (64 - (s + 1)));
    if (r)
        welem = (welem >> r) | (welem << (esize - r));
    for (uint64_t i = 0; i * esize < 64; i++)
        val |= welem << (i * esize);
    if (!sf)
        val &= 0xFFFFFFFFULL;
    out = val;
    return true;
}

bool fp_type(uint32_t w, int &bytes)
{
    const uint32_t t = (w >> 22) & 0x3u;
    if (t == 0)
        bytes = 4;
    else if (t == 1)
        bytes = 8;
    else if (t == 3)
        bytes = 2;
    else
        return false;
    return true;
}

std::string ldst_name(int opc, int size, bool vec, bool load, int mode)
{
    const bool normal = (mode == 0);
    std::string base = load ? "ld" : "st";
    if (mode == 1)
        base += "ur";
    else if (mode == 2)
        base += "tr";
    if (vec)
    {
        if (normal)
            base += "r";
        return base;
    }
    if (opc == 3 && size == 3)
        return "prfm";
    if (opc == 0 || opc == 1)
    {
        if (normal)
            base += "r";
        if (size == 0)
            base += "b";
        else if (size == 1)
            base += "h";
        return base;
    }
    if (opc == 3 && size == 2)
    {
        if (normal)
            base += "r";
        return base;
    }
    if (normal)
        base += "r";
    base += "s";
    base += size == 0 ? "b" : size == 1 ? "h" : "w";
    return base;
}

std::string fp_imm_value(uint32_t imm8, int bytes)
{
    const bool sbit = ((imm8 >> 7) & 1u) != 0;
    const bool b = ((imm8 >> 6) & 1u) != 0;
    const uint32_t e = (imm8 >> 4) & 0x3u;
    const uint32_t f = imm8 & 0xFu;
    char buf[40];
    if (bytes == 4)
    {
        uint32_t exp = ((b ? 0u : 1u) << 7) | ((b ? 0x1Fu : 0u) << 2) | e;
        uint32_t bits = ((sbit ? 1u : 0u) << 31) | (exp << 23) | (f << 19);
        float v = 0;
        memcpy(&v, &bits, 4);
        snprintf(buf, sizeof buf, "%.8g", (double)v);
        return std::string(buf);
    }
    if (bytes == 8)
    {
        uint64_t exp = ((uint64_t)(b ? 0u : 1u) << 10) | ((uint64_t)(b ? 0xFFu : 0u) << 2) | e;
        uint64_t bits = ((uint64_t)(sbit ? 1u : 0u) << 63) | (exp << 52) | ((uint64_t)f << 48);
        double v = 0;
        memcpy(&v, &bits, 8);
        snprintf(buf, sizeof buf, "%.17g", v);
        return std::string(buf);
    }
    return std::string();
}

bool looks_like_entry(uint32_t w)
{
    if (w == 0xD503237Fu || w == 0xD503233Fu || w == 0xD50323BFu || w == 0xD50323FFu)
        return true;
    if ((w & 0xFFC003FFu) == 0xD10003FFu)
        return true;
    if (((w >> 24) == 0xA9u || (w >> 24) == 0x29u) && ((w >> 5) & 0x1Fu) == 31u &&
        ((w >> 22) & 1u) == 0u)
        return true;
    return false;
}

void set_text(Insn &out, const char *mnem, const std::string &ops)
{
    out.text = mnem;
    if (!ops.empty())
    {
        out.text += " ";
        out.text += ops;
    }
}

} // namespace

const char *disasm_kind_name(uint8_t kind)
{
    switch (kind)
    {
    case IK_MOV:
        return "mov";
    case IK_ALU:
        return "alu";
    case IK_CMP:
        return "cmp";
    case IK_LOAD:
        return "load";
    case IK_STORE:
        return "store";
    case IK_ADR:
        return "adr";
    case IK_BRANCH:
        return "branch";
    case IK_CALL:
        return "call";
    case IK_RET:
        return "ret";
    case IK_SYS:
        return "sys";
    case IK_OTHER:
        return "other";
    default:
        return "unknown";
    }
}

void code_callers(const Image &img, const std::vector<uint64_t> &rvas,
                  std::map<uint64_t, std::vector<uint64_t>> &out)
{
    uint64_t lo = 0;
    uint64_t hi = 0;
    std::set<uint64_t> want;
    if (rvas.empty() || !code_text_range(img, lo, hi))
        return;
    for (size_t i = 0; i < rvas.size(); i++)
        want.insert(rvas[i]);
    for (uint64_t va = lo; va + 4 <= hi; va += 4)
    {
        uint32_t w = 0;
        uint64_t trva = 0;
        if (!img.u32(va, w))
            break;
        if ((w & 0xFC000000u) != 0x94000000u)
            continue;
        const int64_t imm = sext((w & 0x3FFFFFFu) << 2, 28);
        const uint64_t t = va + (uint64_t)imm;
        if (t < img.base)
            continue;
        trva = t - img.base;
        if (want.count(trva))
            out[trva].push_back(va - img.base);
    }
}

bool disasm_words(uint64_t va, uint32_t w, Insn &out)
{
    const bool sf = (w >> 31) & 1u;
    const uint32_t rd = w & 0x1Fu;
    const uint32_t rn = (w >> 5) & 0x1Fu;
    const uint32_t rm = (w >> 16) & 0x1Fu;
    const uint32_t op0 = (w >> 25) & 0xFu;
    char buf[256];

    out.va = va;
    out.word = w;
    out.kind = IK_UNKNOWN;
    out.cond = false;
    out.indirect = false;
    out.target = 0;
    out.rd = (int)rd;
    out.rn = (int)rn;
    out.rm = (int)rm;
    out.width = 0;
    out.imm = 0;
    out.text.clear();

    // ---------------------------------------------------------------- ADR / ADRP
    if ((w & 0x1F000000u) == 0x10000000u)
    {
        const bool page = (w >> 31) & 1u;
        const int64_t immlo = (int64_t)((w >> 29) & 0x3u);
        const int64_t immhi = (int64_t)((w >> 5) & 0x7FFFFu);
        int64_t imm = (immhi << 2) | immlo;
        if (page)
        {
            imm <<= 12;
            out.target = (va & ~0xFFFULL) + (uint64_t)imm;
        }
        else
        {
            out.target = va + (uint64_t)imm;
        }
        out.kind = IK_ADR;
        out.rn = -1;
        out.imm = imm;
        snprintf(buf, sizeof buf, "adrp %s, %s", r_x((int)rd, true, false).c_str(),
                 hex64(out.target).c_str());
        if (!page)
            snprintf(buf, sizeof buf, "adr %s, %s", r_x((int)rd, true, false).c_str(),
                     hex64(out.target).c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- add/sub immediate
    if ((w & 0x1F000000u) == 0x11000000u)
    {
        const bool op = (w >> 30) & 1u;
        const bool s = (w >> 29) & 1u;
        const int shift = ((w >> 22) & 1u) ? 12 : 0;
        const uint32_t imm = (w >> 10) & 0xFFFu;
        out.imm = (int64_t)imm << shift;
        out.kind = s ? IK_CMP : IK_ALU;
        if (s && rd == 31u)
        {
            out.rd = -1;
            snprintf(buf, sizeof buf, "%s %s, #0x%x", op ? "cmp" : "cmn",
                     r_x((int)rn, sf, true).c_str(), imm << shift);
        }
        else
        {
            const char *mn = s ? (op ? "subs" : "adds") : (op ? "sub" : "add");
            snprintf(buf, sizeof buf, "%s %s, %s, #0x%x%s", mn, r_x((int)rd, sf, true).c_str(),
                     r_x((int)rn, sf, true).c_str(), imm, shift ? ", lsl #12" : "");
        }
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- logical immediate
    if ((w & 0x1F800000u) == 0x12000000u)
    {
        const uint32_t opc = (w >> 29) & 0x3u;
        const uint32_t n = (w >> 22) & 1u;
        const uint32_t immr = (w >> 16) & 0x3Fu;
        const uint32_t imms = (w >> 10) & 0x3Fu;
        uint64_t bits = 0;
        const char *mn = opc == 0 ? "and" : opc == 1 ? "orr" : opc == 2 ? "eor" : "ands";
        if (!decode_bitmask(sf, n, immr, imms, bits))
        {
            snprintf(buf, sizeof buf, ".word 0x%08x", w);
            out.text = buf;
            return false;
        }
        out.kind = opc == 3 ? IK_CMP : IK_ALU;
        if (opc == 1 && rn == 31)
        {
            out.kind = IK_MOV;
            out.rn = -1;
            snprintf(buf, sizeof buf, "mov %s, %s", r_x((int)rd, sf, true).c_str(),
                     hex64(bits).c_str());
        }
        else if (opc == 3 && rd == 31)
        {
            snprintf(buf, sizeof buf, "tst %s, %s", r_x((int)rn, sf, false).c_str(),
                     hex64(bits).c_str());
        }
        else
        {
            snprintf(buf, sizeof buf, "%s %s, %s, %s", mn, r_x((int)rd, sf, opc == 1).c_str(),
                     r_x((int)rn, sf, false).c_str(), hex64(bits).c_str());
        }
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- move wide
    if ((w & 0x1F800000u) == 0x12800000u)
    {
        const uint32_t opc = (w >> 29) & 0x3u;
        const uint32_t hw = (w >> 21) & 0x3u;
        const uint32_t imm = (w >> 5) & 0xFFFFu;
        const char *mn = opc == 0 ? "movn" : opc == 2 ? "movz" : opc == 3 ? "movk" : "?";
        out.kind = IK_MOV;
        out.rn = -1;
        out.imm = (int64_t)imm;
        snprintf(buf, sizeof buf, "%s %s, #0x%x%s", mn, r_x((int)rd, sf, false).c_str(), imm,
                 hw ? (hw == 1 ? ", lsl #16" : hw == 2 ? ", lsl #32" : ", lsl #48") : "");
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- bitfield
    if ((w & 0x1F800000u) == 0x13000000u)
    {
        const uint32_t opc = (w >> 29) & 0x3u;
        const uint32_t immr = (w >> 16) & 0x3Fu;
        const uint32_t imms = (w >> 10) & 0x3Fu;
        const uint32_t width = sf ? 64u : 32u;
        const std::string d = r_x((int)rd, sf, false);
        const std::string n = r_x((int)rn, sf, false);
        out.kind = IK_ALU;
        if (!sf && (immr > 31u || imms > 31u))
        {
            snprintf(buf, sizeof buf, ".word 0x%08x", w);
            out.kind = IK_UNKNOWN;
            out.text = buf;
            return false;
        }
        if (opc == 0)
        {
            if (immr == 0 && (imms == 7 || imms == 15 || (imms == 31 && sf)))
            {
                const char *mn = imms == 7 ? "sxtb" : imms == 15 ? "sxth" : "sxtw";
                snprintf(buf, sizeof buf, "%s %s, %s", mn, d.c_str(),
                         r_x((int)rn, false, false).c_str());
            }
            else if (imms == width - 1u)
                snprintf(buf, sizeof buf, "asr %s, %s, #%u", d.c_str(), n.c_str(), immr);
            else if (imms + 1u == immr)
                snprintf(buf, sizeof buf, "sbfiz %s, %s, #%u, #%u", d.c_str(), n.c_str(),
                         width - immr, imms + 1);
            else if (imms >= immr)
                snprintf(buf, sizeof buf, "sbfx %s, %s, #%u, #%u", d.c_str(), n.c_str(), immr,
                         imms - immr + 1);
            else
                snprintf(buf, sizeof buf, "sbfiz %s, %s, #%u, #%u", d.c_str(), n.c_str(),
                         width - immr, imms + 1);
        }
        else if (opc == 1)
        {
            if (immr == 0 && imms == width - 1u)
                snprintf(buf, sizeof buf, "mov %s, %s", d.c_str(), n.c_str());
            else if (imms < immr)
                snprintf(buf, sizeof buf, "bfi %s, %s, #%u, #%u", d.c_str(), n.c_str(),
                         width - immr, imms + 1);
            else
                snprintf(buf, sizeof buf, "bfxil %s, %s, #%u, #%u", d.c_str(), n.c_str(), immr,
                         imms - immr + 1);
        }
        else
        {
            if (imms == width - 1u)
                snprintf(buf, sizeof buf, "lsr %s, %s, #%u", d.c_str(), n.c_str(), immr);
            else if (imms + 1u == immr)
                snprintf(buf, sizeof buf, "lsl %s, %s, #%u", d.c_str(), n.c_str(), width - immr);
            else if (immr == 0 && imms == 7u)
                snprintf(buf, sizeof buf, "uxtb %s, %s", d.c_str(), n.c_str());
            else if (immr == 0 && imms == 15u)
                snprintf(buf, sizeof buf, "uxth %s, %s", d.c_str(), n.c_str());
            else if (imms >= immr)
                snprintf(buf, sizeof buf, "ubfx %s, %s, #%u, #%u", d.c_str(), n.c_str(), immr,
                         imms - immr + 1);
            else
                snprintf(buf, sizeof buf, "ubfiz %s, %s, #%u, #%u", d.c_str(), n.c_str(),
                         width - immr, imms + 1);
        }
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- extract
    if ((w & 0x1F800000u) == 0x13800000u)
    {
        const uint32_t o0 = (w >> 29) & 0x3u;
        const uint32_t lsb = (w >> 10) & 0x3Fu;
        out.kind = IK_ALU;
        snprintf(buf, sizeof buf, "%s %s, %s, %s, #0x%x", o0 ? "?extr" : "extr",
                 r_x((int)rd, sf, false).c_str(), r_x((int)rn, sf, false).c_str(),
                 r_x((int)rm, sf, false).c_str(), lsb);
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- B / BL
    if ((w & 0x7C000000u) == 0x14000000u)
    {
        const bool link = (w >> 31) & 1u;
        const int64_t imm = sext((w & 0x3FFFFFFu) << 2, 28);
        out.target = va + (uint64_t)imm;
        out.kind = link ? IK_CALL : IK_BRANCH;
        set_text(out, link ? "bl" : "b", hex64(out.target));
        return true;
    }

    // ---------------------------------------------------------------- CBZ / CBNZ
    if ((w & 0x7E000000u) == 0x34000000u)
    {
        const bool nz = (w >> 24) & 1u;
        const int64_t imm = sext(((w >> 5) & 0x7FFFFu) << 2, 21);
        out.target = va + (uint64_t)imm;
        out.kind = IK_BRANCH;
        out.cond = true;
        out.rd = (int)rd;
        out.rn = -1;
        snprintf(buf, sizeof buf, "%s %s, %s", nz ? "cbnz" : "cbz",
                 r_x((int)rd, sf, false).c_str(), hex64(out.target).c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- TBZ / TBNZ
    if ((w & 0x7E000000u) == 0x36000000u)
    {
        const bool nz = (w >> 24) & 1u;
        const uint32_t bit = (uint32_t)(((w >> 31) & 1u) << 5) | ((w >> 19) & 0x1Fu);
        const int64_t imm = sext(((w >> 5) & 0x3FFFu) << 2, 16);
        out.target = va + (uint64_t)imm;
        out.kind = IK_BRANCH;
        out.cond = true;
        out.imm = (int64_t)bit;
        snprintf(buf, sizeof buf, "%s %s, #%u, %s", nz ? "tbnz" : "tbz",
                 r_x((int)rd, sf, false).c_str(), bit, hex64(out.target).c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- B.cond
    if ((w & 0xFF000010u) == 0x54000000u)
    {
        const uint32_t c = w & 0xFu;
        const int64_t imm = sext(((w >> 5) & 0x7FFFFu) << 2, 21);
        out.target = va + (uint64_t)imm;
        out.kind = IK_BRANCH;
        out.cond = true;
        out.imm = (int64_t)c;
        snprintf(buf, sizeof buf, "b.%s %s", kCond[c], hex64(out.target).c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- indirect branches
    if ((w & 0xFFFFFC1Fu) == 0xD61F0000u)
    {
        out.kind = IK_BRANCH;
        out.indirect = true;
        out.rn = -1;
        set_text(out, "br", r_x((int)rn, true, false));
        return true;
    }
    if ((w & 0xFFFFFC1Fu) == 0xD63F0000u)
    {
        out.kind = IK_CALL;
        out.indirect = true;
        out.rn = -1;
        set_text(out, "blr", r_x((int)rn, true, false));
        return true;
    }
    if ((w & 0xFFFFFC1Fu) == 0xD65F0000u)
    {
        out.kind = IK_RET;
        out.indirect = true;
        out.rn = -1;
        set_text(out, "ret", rn == 30 ? std::string() : r_x((int)rn, true, false));
        return true;
    }
    if ((w & 0xFFFFFC1Fu) == 0xD71F0000u)
    {
        out.kind = IK_BRANCH;
        out.indirect = true;
        out.rn = -1;
        set_text(out, "braa", r_x((int)rn, true, false) + ", " + r_x((int)rm, true, false));
        return true;
    }
    if ((w & 0xFFFFFC1Fu) == 0xD73F0000u)
    {
        out.kind = IK_CALL;
        out.indirect = true;
        out.rn = -1;
        set_text(out, "blraa", r_x((int)rn, true, false) + ", " + r_x((int)rm, true, false));
        return true;
    }

    // ---------------------------------------------------------------- exception / system
    if ((w & 0xFFE0001Fu) == 0xD4000001u)
    {
        out.kind = IK_SYS;
        snprintf(buf, sizeof buf, "svc #0x%x", (w >> 5) & 0xFFFFu);
        out.text = buf;
        return true;
    }
    if ((w & 0xFFE0001Fu) == 0xD4200000u)
    {
        out.kind = IK_SYS;
        snprintf(buf, sizeof buf, "brk #0x%x", (w >> 5) & 0xFFFFu);
        out.text = buf;
        return true;
    }
    if ((w & 0xFFFFF01Fu) == 0xD503201Fu)
    {
        const uint32_t imm = (w >> 5) & 0x7Fu;
        static const char *kHints[16] = {"nop",  "yield", "wfe",     "wfi",     "sev",
                                         "sevl", "dgh",   "xpaclri", "pacia1716", "?"};
        out.kind = IK_SYS;
        if (imm == 4)
            snprintf(buf, sizeof buf, "sev");
        else if (imm == 12)
            snprintf(buf, sizeof buf, "paciasp");
        else if (imm == 13)
            snprintf(buf, sizeof buf, "autiasp");
        else if (imm == 14)
            snprintf(buf, sizeof buf, "pacibsp");
        else if (imm == 15)
            snprintf(buf, sizeof buf, "autibsp");
        else if (imm == 5)
            snprintf(buf, sizeof buf, "sevl");
        else if (imm == 0)
            snprintf(buf, sizeof buf, "nop");
        else if (imm == 1)
            snprintf(buf, sizeof buf, "yield");
        else if (imm == 2)
            snprintf(buf, sizeof buf, "wfe");
        else if (imm == 3)
            snprintf(buf, sizeof buf, "wfi");
        else if (imm < 9)
            snprintf(buf, sizeof buf, "%s", kHints[imm]);
        else
            snprintf(buf, sizeof buf, "hint #0x%x", imm);
        out.text = buf;
        return true;
    }
    if ((w & 0xFFFFF0FFu) == 0xD503309Fu || (w & 0xFFFFF0FFu) == 0xD50330BFu ||
        (w & 0xFFFFF0FFu) == 0xD50330DFu)
    {
        const uint32_t crm = (w >> 8) & 0xFu;
        static const char *kBar[16] = {"#0",   "oshld", "oshst", "osh",   "0x4", "nshld",
                                       "nshst", "nsh",   "0x8",   "ishld", "ishst", "ish",
                                       "0xc",  "ld",    "st",    "sy"};
        const uint32_t op2 = w & 0xFFFFF0FFu;
        const char *mn = op2 == 0xD503309Fu ? "dsb" : op2 == 0xD50330BFu ? "dmb" : "isb";
        out.kind = IK_SYS;
        snprintf(buf, sizeof buf, "%s %s", mn, kBar[crm & 0xF]);
        out.text = buf;
        return true;
    }
    if ((w & 0xFFF00000u) == 0xD5300000u || (w & 0xFFF00000u) == 0xD5100000u)
    {
        const bool read = (w & 0xFFF00000u) == 0xD5300000u;
        out.kind = IK_SYS;
        snprintf(buf, sizeof buf, "%s %s, <sysreg 0x%x:%x:%x:%x>", read ? "mrs" : "msr",
                 r_x((int)rd, true, false).c_str(), (w >> 16) & 1u, (w >> 5) & 0x7u,
                 (w >> 19) & 0xFu, (w >> 10) & 0xFu);
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- load/store exclusive and ordered
    if ((w & 0x3F000000u) == 0x08000000u)
    {
        static const struct
        {
            uint32_t val;
            const char *mn;
            bool store;
            bool pair;
        } kEx[8] = {
            {0x08507C00u, "ldxr", false, false},  {0x0850FC00u, "ldaxr", false, false},
            {0x08007C00u, "stxr", true, false},   {0x0800FC00u, "stlxr", true, false},
            {0x08D0FC00u, "ldar", false, false},  {0x0890FC00u, "stlr", true, false},
            {0x08700000u, "ldxp", false, true},   {0x08200000u, "stxp", true, true},
        };
        const uint32_t key = w & 0x3FF0FC00u;
        const uint32_t size = (w >> 30) & 0x3u;
        const uint32_t rs = (w >> 16) & 0x1Fu;
        const uint32_t rt2 = (w >> 10) & 0x1Fu;
        for (int i = 0; i < 8; i++)
        {
            if (kEx[i].val != key)
                continue;
            const char *suffix = size == 0 ? "b" : size == 1 ? "h" : "";
            const bool wide = (size == 3);
            out.kind = kEx[i].store ? IK_STORE : IK_LOAD;
            out.width = 1 << size;
            if (kEx[i].pair)
                snprintf(buf, sizeof buf, "%s%s %s, %s, [%s]", kEx[i].mn, suffix,
                         kEx[i].store ? r_x((int)rs, false, false).c_str()
                                      : r_x((int)rd, wide, false).c_str(),
                         r_x((int)rt2, wide, false).c_str(),
                         r_x((int)rn, true, true).c_str());
            else if (kEx[i].store)
                snprintf(buf, sizeof buf, "%s%s %s, %s, [%s]", kEx[i].mn, suffix,
                         r_x((int)rs, false, false).c_str(),
                         r_x((int)rd, wide, false).c_str(),
                         r_x((int)rn, true, true).c_str());
            else
                snprintf(buf, sizeof buf, "%s%s %s, [%s]", kEx[i].mn, suffix,
                         r_x((int)rd, wide, false).c_str(),
                         r_x((int)rn, true, true).c_str());
            out.text = buf;
            return true;
        }
    }

    // ---------------------------------------------------------------- LDR (literal)
    if ((w & 0x3B000000u) == 0x18000000u)
    {
        const uint32_t opc = (w >> 30) & 0x3u;
        const bool vec = ((w >> 26) & 1u) != 0;
        const int64_t imm = sext(((w >> 5) & 0x7FFFFu) << 2, 21);
        out.target = va + (uint64_t)imm;
        out.kind = IK_LOAD;
        out.width = vec ? (opc == 3 ? 16 : opc == 1 ? 8 : 4) : (opc == 1 ? 8 : 4);
        if (vec)
            snprintf(buf, sizeof buf, "ldr %s, %s",
                     r_v((int)rd, out.width).c_str(), hex64(out.target).c_str());
        else if (opc == 0)
            snprintf(buf, sizeof buf, "ldr w%u, %s", rd, hex64(out.target).c_str());
        else if (opc == 1)
            snprintf(buf, sizeof buf, "ldr x%u, %s", rd, hex64(out.target).c_str());
        else if (opc == 2)
            snprintf(buf, sizeof buf, "ldrsw x%u, %s", rd, hex64(out.target).c_str());
        else
            snprintf(buf, sizeof buf, "prfm #%u, %s", rd, hex64(out.target).c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- LDP / STP
    if ((w & 0x3A000000u) == 0x28000000u)
    {
        const uint32_t opc = (w >> 30) & 0x3u;
        const bool vec = ((w >> 26) & 1u) != 0;
        const bool load = ((w >> 22) & 1u) != 0;
        const uint32_t idx = (w >> 23) & 0x3u;
        const uint32_t rt2 = (w >> 10) & 0x1Fu;
        const int scale = vec ? (opc == 0 ? 2 : opc == 1 ? 3 : 4) : (opc == 2 ? 3 : 2);
        const uint64_t raw = (w >> 15) & 0x7Fu;
        const int64_t off = sext(raw, 7) << scale;
        const bool w32 = (!vec && opc == 0);
        std::string a;
        std::string b;
        out.kind = load ? IK_LOAD : IK_STORE;
        out.width = 1 << scale;
        if (vec)
        {
            const int bytes = 1 << scale;
            a = r_v((int)rd, bytes);
            b = r_v((int)rt2, bytes);
        }
        else if (opc == 1)
        {
            a = r_x((int)rd, true, false);
            b = r_x((int)rt2, true, false);
        }
        else
        {
            a = r_x((int)rd, !w32, false);
            b = r_x((int)rt2, !w32, false);
        }
        const char *mn;
        if (!vec && opc == 1)
            mn = "ldpsw";
        else if (idx == 0)
            mn = load ? "ldnp" : "stnp";
        else
            mn = load ? "ldp" : "stp";
        if (idx == 1)
            snprintf(buf, sizeof buf, "%s %s, %s, [%s], #%s", mn, a.c_str(), b.c_str(),
                     r_x((int)((w >> 5) & 0x1Fu), true, true).c_str(), hex_off(off).c_str());
        else
            snprintf(buf, sizeof buf, "%s %s, %s, [%s, #%s]%s", mn, a.c_str(), b.c_str(),
                     r_x((int)((w >> 5) & 0x1Fu), true, true).c_str(), hex_off(off).c_str(),
                     idx == 3 ? "!" : "");
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- LD/ST unsigned immediate
    if ((w & 0x3B000000u) == 0x39000000u)
    {
        const uint32_t size = (w >> 30) & 0x3u;
        const uint32_t opc = (w >> 22) & 0x3u;
        const bool vec = ((w >> 26) & 1u) != 0;
        uint64_t off = ((w >> 10) & 0xFFFu) << size;
        int bytes = 1 << size;
        bool load = opc != 0;
        if (vec)
        {
            if (opc >= 2u)
            {
                bytes = 16;
                load = opc == 3u;
                off = ((w >> 10) & 0xFFFu) << 4;
            }
            else
            {
                bytes = 1 << size;
                load = opc == 1u;
            }
        }
        std::string r;
        out.kind = load ? IK_LOAD : IK_STORE;
        out.width = bytes;
        out.imm = (int64_t)off;
        if (vec)
            r = r_v((int)rd, bytes);
        else if (opc == 0 || opc == 1)
            r = r_x((int)rd, size == 3, false);
        else if (opc == 2)
            r = r_x((int)rd, true, false);
        else
            r = r_x((int)rd, false, false);
        snprintf(buf, sizeof buf, "%s %s, [%s, #%s]", ldst_name(opc, size, vec, load, 0).c_str(),
                 r.c_str(), r_x((int)rn, true, true).c_str(), hex_off((int64_t)off).c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- LD/ST imm9 (unscaled/pre/post)
    if ((w & 0x3B200000u) == 0x38000000u)
    {
        const uint32_t size = (w >> 30) & 0x3u;
        const uint32_t opc = (w >> 22) & 0x3u;
        const bool vec = ((w >> 26) & 1u) != 0;
        const uint32_t mode = (w >> 10) & 0x3u;
        int64_t off = sext((w >> 12) & 0x1FFu, 9);
        int bytes = 1 << size;
        bool load = opc != 0;
        if (vec)
        {
            if (opc >= 2u)
            {
                bytes = 16;
                load = opc == 3u;
            }
            else
            {
                bytes = 1 << size;
                load = opc == 1u;
            }
        }
        const int mn_mode = mode == 0 ? 1 : (mode == 2 ? 2 : 0);
        std::string r;
        out.kind = load ? IK_LOAD : IK_STORE;
        out.width = bytes;
        out.imm = off;
        if (vec)
            r = r_v((int)rd, bytes);
        else if (opc == 0 || opc == 1)
            r = r_x((int)rd, size == 3, false);
        else if (opc == 2)
            r = r_x((int)rd, true, false);
        else
            r = r_x((int)rd, false, false);
        if (mode == 1)
            snprintf(buf, sizeof buf, "%s %s, [%s], #%s", ldst_name(opc, size, vec, load, 0).c_str(),
                     r.c_str(), r_x((int)rn, true, true).c_str(), hex_off(off).c_str());
        else if (mode == 3)
            snprintf(buf, sizeof buf, "%s %s, [%s, #%s]!", ldst_name(opc, size, vec, load, 0).c_str(),
                     r.c_str(), r_x((int)rn, true, true).c_str(), hex_off(off).c_str());
        else
            snprintf(buf, sizeof buf, "%s %s, [%s, #%s]", ldst_name(opc, size, vec, load, mn_mode).c_str(),
                     r.c_str(), r_x((int)rn, true, true).c_str(), hex_off(off).c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- LD/ST register offset
    if ((w & 0x3B200C00u) == 0x38200800u)
    {
        const uint32_t size = (w >> 30) & 0x3u;
        const uint32_t opc = (w >> 22) & 0x3u;
        const bool vec = ((w >> 26) & 1u) != 0;
        const uint32_t option = (w >> 13) & 0x7u;
        int bytes = 1 << size;
        bool load = opc != 0;
        if (vec)
        {
            if (opc >= 2u)
            {
                bytes = 16;
                load = opc == 3u;
            }
            else
            {
                bytes = 1 << size;
                load = opc == 1u;
            }
        }
        std::string r;
        out.kind = load ? IK_LOAD : IK_STORE;
        out.width = bytes;
        if (vec)
            r = r_v((int)rd, bytes);
        else if (opc == 0 || opc == 1)
            r = r_x((int)rd, size == 3, false);
        else if (opc == 2)
            r = r_x((int)rd, true, false);
        else
            r = r_x((int)rd, false, false);
        const bool shifted = ((w >> 12) & 1u) != 0;
        if (shifted)
            snprintf(buf, sizeof buf, "%s %s, [%s, %s, lsl #%d]",
                     ldst_name(opc, size, vec, load, 0).c_str(), r.c_str(),
                     r_x((int)rn, true, true).c_str(), r_x((int)rm, true, false).c_str(), size);
        else if (option == 3)
            snprintf(buf, sizeof buf, "%s %s, [%s, %s]", ldst_name(opc, size, vec, load, 0).c_str(),
                     r.c_str(), r_x((int)rn, true, true).c_str(), r_x((int)rm, true, false).c_str());
        else
            snprintf(buf, sizeof buf, "%s %s, [%s, %s, %s]",
                     ldst_name(opc, size, vec, load, 0).c_str(), r.c_str(),
                     r_x((int)rn, true, true).c_str(), r_x((int)rm, option >= 3, false).c_str(),
                     kExt[option]);
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- logical (shifted register)
    if ((w & 0x1F000000u) == 0x0A000000u)
    {
        const uint32_t opc = (w >> 29) & 0x3u;
        const bool nbit = ((w >> 21) & 1u) != 0;
        const uint32_t shift = (w >> 22) & 0x3u;
        const uint32_t amt = (w >> 10) & 0x3Fu;
        static const char *kLog[8] = {"and", "bic", "orr", "orn", "eor", "eon", "ands", "bics"};
        const char *mn = kLog[opc * 2 + (nbit ? 1 : 0)];
        out.kind = opc == 3 ? IK_CMP : IK_ALU;
        std::string ops = r_x((int)rd, sf, opc == 1) + ", " + r_x((int)rn, sf, false) + ", " +
                          r_x((int)rm, sf, false);
        if (amt)
            ops += ", " + std::string(kShift[shift]) + " #" + std::to_string(amt);
        if (opc == 1 && rn == 31 && !nbit)
        {
            out.kind = IK_MOV;
            std::string o = r_x((int)rd, sf, true) + ", " + r_x((int)rm, sf, false);
            if (amt)
                o += ", " + std::string(kShift[shift]) + " #" + std::to_string(amt);
            set_text(out, "mov", o);
            return true;
        }
        if (opc == 3 && rd == 31 && !nbit)
        {
            out.kind = IK_CMP;
            set_text(out, "tst", r_x((int)rn, sf, false) + ", " + r_x((int)rm, sf, false));
            return true;
        }
        set_text(out, mn, ops);
        return true;
    }

    // ---------------------------------------------------------------- add/sub (shifted register)
    if ((w & 0x1F200000u) == 0x0B000000u)
    {
        const bool op = (w >> 30) & 1u;
        const bool s = (w >> 29) & 1u;
        const uint32_t shift = (w >> 22) & 0x3u;
        const uint32_t amt = (w >> 10) & 0x3Fu;
        out.kind = s ? IK_CMP : IK_ALU;
        std::string rm_s = r_x((int)rm, sf, false);
        if (amt)
            rm_s += ", " + std::string(kShift[shift]) + " #" + std::to_string(amt);
        if (s && rd == 31u)
        {
            out.rd = -1;
            set_text(out, op ? "cmp" : "cmn", r_x((int)rn, sf, true) + ", " + rm_s);
            return true;
        }
        set_text(out, s ? (op ? "subs" : "adds") : (op ? "sub" : "add"),
                 r_x((int)rd, sf, true) + ", " + r_x((int)rn, sf, true) + ", " + rm_s);
        return true;
    }

    // ---------------------------------------------------------------- add/sub (extended register)
    if ((w & 0x1F200000u) == 0x0B200000u)
    {
        const bool op = (w >> 30) & 1u;
        const bool s = (w >> 29) & 1u;
        const uint32_t option = (w >> 13) & 0x7u;
        const uint32_t amt = (w >> 10) & 0x7u;
        const bool x_form = option >= 3;
        std::string rm_s = r_x((int)rm, x_form, false) + ", " + std::string(kExt[option]);
        if (amt)
            rm_s += " #" + std::to_string(amt);
        out.kind = s ? IK_CMP : IK_ALU;
        if (s && rd == 31u)
        {
            out.rd = -1;
            set_text(out, op ? "cmp" : "cmn", r_x((int)rn, sf, true) + ", " + rm_s);
            return true;
        }
        set_text(out, s ? (op ? "subs" : "adds") : (op ? "sub" : "add"),
                 r_x((int)rd, sf, true) + ", " + r_x((int)rn, sf, true) + ", " + rm_s);
        return true;
    }

    // ---------------------------------------------------------------- add/sub with carry
    if ((w & 0x1FE00000u) == 0x1A000000u)
    {
        const bool op = (w >> 30) & 1u;
        const bool s = (w >> 29) & 1u;
        static const char *kCarry[4] = {"adc", "adcs", "sbc", "sbcs"};
        out.kind = IK_ALU;
        set_text(out, kCarry[op * 2 + (s ? 1 : 0)],
                 r_x((int)rd, sf, false) + ", " + r_x((int)rn, sf, false) + ", " +
                     r_x((int)rm, sf, false));
        return true;
    }

    // ---------------------------------------------------------------- conditional select
    if ((w & 0x1FE00000u) == 0x1A800000u)
    {
        const uint32_t op = (w >> 29) & 0x3u;
        const uint32_t cond = (w >> 12) & 0xFu;
        static const char *kSel[4] = {"csel", "csinc", "csinv", "csneg"};
        out.kind = IK_ALU;
        snprintf(buf, sizeof buf, "%s %s, %s, %s, %s", kSel[op],
                 r_x((int)rd, sf, false).c_str(), r_x((int)rn, sf, false).c_str(),
                 r_x((int)rm, sf, false).c_str(), kCond[cond]);
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- data-processing (3 source)
    if ((w & 0x1F000000u) == 0x1B000000u)
    {
        const uint32_t op54 = (w >> 29) & 0x3u;
        const bool un = ((w >> 23) & 1u) != 0;
        const bool sub = ((w >> 15) & 1u) != 0;
        const uint32_t ra = (w >> 10) & 0x1Fu;
        out.kind = IK_ALU;
        if (op54 == 0)
        {
            set_text(out, sub ? "msub" : "madd",
                     r_x((int)rd, sf, false) + ", " + r_x((int)rn, sf, false) + ", " +
                         r_x((int)rm, sf, false) + ", " + r_x((int)ra, sf, false));
            return true;
        }
        if (op54 == 1)
        {
            const char *mn = un ? (sub ? "umsub" : "umaddl") : (sub ? "smsubl" : "smaddl");
            snprintf(buf, sizeof buf, "%s %s, %s, %s, %s", mn, r_x((int)rd, true, false).c_str(),
                     r_x((int)rn, false, false).c_str(), r_x((int)rm, false, false).c_str(),
                     r_x((int)ra, true, false).c_str());
            out.text = buf;
            return true;
        }
        set_text(out, un ? "umulh" : "smulh",
                 r_x((int)rd, true, false) + ", " + r_x((int)rn, true, false) + ", " +
                     r_x((int)rm, true, false));
        return true;
    }

    // ---------------------------------------------------------------- data-processing (2 source)
    if ((w & 0x1FE00000u) == 0x1AC00000u)
    {
        const uint32_t opc = (w >> 10) & 0x3Fu;
        static const char *kBin[16] = {"?", "?", "udiv", "sdiv", "?", "?", "?", "?",
                                       "lslv", "lsrv", "asrv", "rorv"};
        const char *mn = opc < 16 ? kBin[opc] : "?";
        out.kind = IK_ALU;
        snprintf(buf, sizeof buf, "%s %s, %s, %s", mn, r_x((int)rd, sf, false).c_str(),
                 r_x((int)rn, sf, false).c_str(), r_x((int)rm, sf, false).c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- data-processing (1 source)
    if ((w & 0x7FE00000u) == 0x5AC00000u)
    {
        const uint32_t opc = (w >> 10) & 0x3Fu;
        const char *mn = opc == 0 ? "rbit" : opc == 1 ? "rev16" : opc == 2 ? (sf ? "rev" : "rev32")
                                    : opc == 4 ? "clz" : opc == 5 ? "cls" : "?";
        out.kind = IK_ALU;
        snprintf(buf, sizeof buf, "%s %s, %s", mn, r_x((int)rd, sf, false).c_str(),
                 r_x((int)rn, sf, false).c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- FP compare
    if ((w & 0x7F200C00u) == 0x1E200000u && (w & 0x2000u))
    {
        int bytes = 0;
        if (!fp_type(w, bytes))
        {
            snprintf(buf, sizeof buf, ".word 0x%08x", w);
            out.text = buf;
            return false;
        }
        out.kind = IK_CMP;
        if (w & 0x8u)
            snprintf(buf, sizeof buf, "fcmp %s, #0.0", r_v((int)rn, bytes).c_str());
        else
            snprintf(buf, sizeof buf, "fcmp %s, %s", r_v((int)rn, bytes).c_str(),
                     r_v((int)rm, bytes).c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- FP (2 source)
    if ((w & 0xFF200C00u) == 0x1E200800u)
    {
        int bytes = 0;
        static const char *kFP2[16] = {"fmul", "fdiv", "fadd", "fsub", "fmax", "fmin", "?",   "?",
                                       "fnmul", "?",  "?",    "?",    "?",    "?",    "?", "?"};
        if (!fp_type(w, bytes))
        {
            snprintf(buf, sizeof buf, ".word 0x%08x", w);
            out.text = buf;
            return false;
        }
        const uint32_t opc = (w >> 12) & 0xFu;
        out.kind = IK_ALU;
        snprintf(buf, sizeof buf, "%s %s, %s, %s", kFP2[opc], r_v((int)rd, bytes).c_str(),
                 r_v((int)rn, bytes).c_str(), r_v((int)rm, bytes).c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- FP (1 source)
    if ((w & 0xFF207C00u) == 0x1E204000u)
    {
        int bytes = 0;
        static const char *kFP1[16] = {"fmov", "fabs", "fneg", "fsqrt", "fcvt", "fcvt", "?", "?",
                                       "frintn", "frintp", "frintm", "frintz", "frinta", "?", "frintx", "frinti"};
        if (!fp_type(w, bytes))
        {
            snprintf(buf, sizeof buf, ".word 0x%08x", w);
            out.text = buf;
            return false;
        }
        const uint32_t opc = (w >> 15) & 0x3Fu;
        const char *mn = opc < 16 ? kFP1[opc] : "?";
        int dst_bytes = bytes;
        if (opc == 4)
            dst_bytes = 2;
        else if (opc == 5)
            dst_bytes = bytes == 4 ? 8 : 4;
        out.kind = IK_ALU;
        snprintf(buf, sizeof buf, "%s %s, %s", mn, r_v((int)rd, dst_bytes).c_str(),
                 r_v((int)rn, bytes).c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- FP conditional select
    if ((w & 0x7F200C00u) == 0x1E200C00u)
    {
        int bytes = 0;
        if (!fp_type(w, bytes))
        {
            snprintf(buf, sizeof buf, ".word 0x%08x", w);
            out.text = buf;
            return false;
        }
        const uint32_t cond = (w >> 12) & 0xFu;
        out.kind = IK_ALU;
        snprintf(buf, sizeof buf, "fcsel %s, %s, %s, %s", r_v((int)rd, bytes).c_str(),
                 r_v((int)rn, bytes).c_str(), r_v((int)rm, bytes).c_str(), kCond[cond]);
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- FP (3 source)
    if ((w & 0x5F000000u) == 0x1F000000u)
    {
        int bytes = 0;
        const bool o1 = ((w >> 21) & 1u) != 0;
        const bool o0 = ((w >> 15) & 1u) != 0;
        const uint32_t ra = (w >> 10) & 0x1Fu;
        const char *mn =
            !o1 && !o0 ? "fmadd" : !o1 && o0 ? "fmsub" : o1 && !o0 ? "fnmadd" : "fnmsub";
        if (!fp_type(w, bytes))
        {
            snprintf(buf, sizeof buf, ".word 0x%08x", w);
            out.text = buf;
            return false;
        }
        out.kind = IK_ALU;
        snprintf(buf, sizeof buf, "%s %s, %s, %s, %s", mn, r_v((int)rd, bytes).c_str(),
                 r_v((int)rn, bytes).c_str(), r_v((int)rm, bytes).c_str(),
                 r_v((int)ra, bytes).c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- FP immediate
    if ((w & 0x7F201000u) == 0x1E201000u)
    {
        int bytes = 0;
        if (!fp_type(w, bytes) || bytes == 2)
        {
            snprintf(buf, sizeof buf, ".word 0x%08x", w);
            out.text = buf;
            return false;
        }
        const std::string val = fp_imm_value((w >> 13) & 0xFFu, bytes);
        out.kind = IK_ALU;
        snprintf(buf, sizeof buf, "fmov %s, #%s", r_v((int)rd, bytes).c_str(), val.c_str());
        out.text = buf;
        return true;
    }

    // ---------------------------------------------------------------- zero word / padding
    if (w == 0u)
    {
        out.kind = IK_SYS;
        out.text = "udf #0";
        return true;
    }

    // ---------------------------------------------------------------- FP <-> integer conversion
    if ((w & 0x7F200000u) == 0x1E200000u)
    {
        int bytes = 0;
        const uint32_t opc = (w >> 16) & 0x1Fu;
        const char *mn = nullptr;
        bool to_fp = false;
        if (opc == 2)
        {
            mn = "scvtf";
            to_fp = true;
        }
        else if (opc == 3)
        {
            mn = "ucvtf";
            to_fp = true;
        }
        else if (opc == 24)
            mn = "fcvtzs";
        else if (opc == 25)
            mn = "fcvtzu";
        else if (opc == 7)
        {
            mn = "fmov";
            to_fp = true;
        }
        else if (opc == 6)
            mn = "fmov";
        if (!mn || !fp_type(w, bytes))
        {
            snprintf(buf, sizeof buf, ".word 0x%08x", w);
            out.text = buf;
            return false;
        }
        out.kind = IK_ALU;
        snprintf(buf, sizeof buf, "%s %s, %s", mn,
                 to_fp ? r_v((int)rd, bytes).c_str() : r_x((int)rd, sf, false).c_str(),
                 to_fp ? r_x((int)rn, sf, false).c_str() : r_v((int)rn, bytes).c_str());
        out.text = buf;
        return true;
    }

    (void)op0;
    (void)fp_type;
    snprintf(buf, sizeof buf, ".word 0x%08x", w);
    out.text = buf;
    return false;
}

bool disasm_insn(const Image &img, uint64_t va, Insn &out)
{
    uint32_t w = 0;
    if (!img.u32(va, w))
        return false;
    return disasm_words(va, w, out);
}

bool disasm_function(const Image &img, uint64_t start, size_t max_insns, Func &out)
{
    uint64_t lo = 0;
    uint64_t hi = 0;
    uint64_t va = start;
    uint64_t furthest = start;
    bool seen_ret = false;
    out.start = start;
    out.end = start;
    out.truncated = false;
    out.insns.clear();
    if (!code_text_range(img, lo, hi))
        return false;
    if (start < lo || start + 4 > hi)
        return false;
    while (va + 4 <= hi)
    {
        uint32_t w = 0;
        Insn in;
        if (!img.u32(va, w))
            break;
        disasm_words(va, w, in);
        if (in.cond && in.kind == IK_BRANCH && in.target > va && in.target >= lo && in.target < hi &&
            in.target > furthest)
            furthest = in.target;
        out.insns.push_back(in);
        va += 4;
        if (out.insns.size() >= max_insns)
        {
            out.truncated = true;
            break;
        }
        if (in.kind == IK_RET)
            seen_ret = true;
        if (in.kind == IK_BRANCH && !in.cond && !in.indirect && in.target &&
            (in.target < start || in.target > start + 0x2000))
            break;
        const bool terminal = (in.kind == IK_RET) ||
                              (in.kind == IK_BRANCH && !in.cond && !in.indirect);
        if (terminal && va >= furthest)
        {
            uint32_t nxt = 0;
            if (!img.u32(va, nxt))
                break;
            if (nxt == 0u || nxt == 0xD503201Fu || looks_like_entry(nxt))
                break;
        }
        if (seen_ret && va + 16 <= hi)
        {
            uint32_t nx[4] = {0, 0, 0, 0};
            int score = 0;
            bool ok = true;
            for (int k = 0; k < 4; k++)
            {
                if (!img.u32(va + (uint64_t)k * 4, nx[k]))
                {
                    ok = false;
                    break;
                }
                if (looks_like_entry(nx[k]))
                    score++;
            }
            if (ok && nx[0] == 0u)
                break;
            if (ok && looks_like_entry(nx[0]) && score >= 2)
                break;
        }
    }
    out.end = va;
    return !out.insns.empty();
}

void disasm_listing(const Func &f, uint64_t base, const NameTable &names, std::string &out)
{
    char line[512];
    for (size_t i = 0; i < f.insns.size(); i++)
    {
        const Insn &in = f.insns[i];
        std::string text = in.text;
        if (in.target)
        {
            const std::string abs = hex64(in.target);
            const std::string rel = hex64(in.target - base);
            const size_t at = text.rfind(abs);
            if (at != std::string::npos)
                text.replace(at, abs.size(), rel);
        }
        snprintf(line, sizeof line, "`0x%06llx`  `%08x`  `%s`",
                 (unsigned long long)(in.va - base), in.word, text.c_str());
        out += line;
        if ((in.kind == IK_CALL || in.kind == IK_BRANCH) && in.target)
        {
            const std::string *nm = names.lookup(in.target - base);
            if (nm)
            {
                out += "  ; ";
                out += *nm;
            }
            else if (in.kind == IK_CALL)
            {
                out += "  ; sub_";
                out += hex64(in.target - base).substr(2);
            }
        }
        if (in.kind == IK_ADR && in.target)
        {
            uint64_t delta = 0;
            const std::string *nm = names.nearest(in.target - base, &delta);
            if (nm)
            {
                out += "  ; ";
                out += *nm;
                if (delta)
                {
                    out += "+";
                    out += hex64(delta);
                }
            }
        }
        out += "\n";
    }
    if (f.truncated)
        out += "\n(cut: instruction cap reached)\n";
}

void NameTable::add(uint64_t rva, const std::string &name)
{
    CodeName c;
    c.rva = rva;
    c.name = name;
    names.push_back(c);
}

void NameTable::finalize()
{
    std::sort(names.begin(), names.end(),
              [](const CodeName &a, const CodeName &b) { return a.rva < b.rva; });
}

const std::string *NameTable::lookup(uint64_t rva) const
{
    size_t lo = 0;
    size_t hi = names.size();
    while (lo < hi)
    {
        const size_t mid = lo + (hi - lo) / 2;
        if (names[mid].rva == rva)
            return &names[mid].name;
        if (names[mid].rva < rva)
            lo = mid + 1;
        else
            hi = mid;
    }
    return nullptr;
}

const std::string *NameTable::nearest(uint64_t rva, uint64_t *delta) const
{
    if (names.empty())
        return nullptr;
    size_t lo = 0;
    size_t hi = names.size();
    while (lo < hi)
    {
        const size_t mid = lo + (hi - lo) / 2;
        if (names[mid].rva <= rva)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo == 0)
        return nullptr;
    const CodeName &c = names[lo - 1];
    if (rva - c.rva > 0x20000)
        return nullptr;
    if (delta)
        *delta = rva - c.rva;
    return &c.name;
}

std::string NameTable::label_for(uint64_t rva) const
{
    const std::string *nm = lookup(rva);
    if (nm)
        return *nm;
    std::string s = "sub_";
    char b[32];
    snprintf(b, sizeof b, "%llx", (unsigned long long)rva);
    s += b;
    return s;
}

} // namespace rcl
