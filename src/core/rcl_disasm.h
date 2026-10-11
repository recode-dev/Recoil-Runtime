#ifndef RCL_DISASM_H
#define RCL_DISASM_H

#include "rcl_scan.h"

#include <stdint.h>
#include <map>
#include <string>
#include <vector>

namespace rcl
{

enum InsnKind
{
    IK_UNKNOWN = 0,
    IK_OTHER,
    IK_MOV,
    IK_ALU,
    IK_CMP,
    IK_LOAD,
    IK_STORE,
    IK_ADR,
    IK_BRANCH,
    IK_CALL,
    IK_RET,
    IK_SYS,
};

struct Insn
{
    uint64_t va = 0;
    uint32_t word = 0;
    uint8_t kind = IK_UNKNOWN;
    bool cond = false;
    bool indirect = false;
    uint64_t target = 0;
    int rd = -1;
    int rn = -1;
    int rm = -1;
    int width = 0;
    int64_t imm = 0;
    std::string text;
};

struct Func
{
    uint64_t start = 0;
    uint64_t end = 0;
    bool truncated = false;
    std::vector<Insn> insns;
    size_t size() const
    {
        return insns.size();
    }
};

struct CodeName
{
    uint64_t rva = 0;
    std::string name;
};

struct NameTable
{
    std::vector<CodeName> names;

    void add(uint64_t rva, const std::string &name);
    void finalize();
    const std::string *lookup(uint64_t rva) const;
    const std::string *nearest(uint64_t rva, uint64_t *delta) const;
    std::string label_for(uint64_t rva) const;
};

const char *disasm_kind_name(uint8_t kind);

bool disasm_words(uint64_t va, uint32_t w, Insn &out);
bool disasm_insn(const Image &img, uint64_t va, Insn &out);
bool disasm_function(const Image &img, uint64_t start, size_t max_insns, Func &out);
void disasm_listing(const Func &f, uint64_t base, const NameTable &names, std::string &out);
void code_callers(const Image &img, const std::vector<uint64_t> &rvas,
                  std::map<uint64_t, std::vector<uint64_t>> &out);

} // namespace rcl

#endif
