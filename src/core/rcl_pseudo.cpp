#include "rcl_pseudo.h"

#include <map>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

namespace rcl
{

namespace
{

std::string pv(int r, bool w)
{
    char b[24];
    if (r == 29)
        return "fp";
    if (r == 30)
        return "lr";
    if (r == 31)
        return w ? "wsp" : "sp";
    if (r < 0)
        return "?";
    if (r < 8)
        snprintf(b, sizeof b, "a%d", r);
    else
        snprintf(b, sizeof b, "v%d", r);
    return std::string(b);
}

std::string wtype(int width)
{
    switch (width)
    {
    case 1:
        return "uint8_t";
    case 2:
        return "uint16_t";
    case 4:
        return "uint32_t";
    case 8:
        return "uint64_t";
    case 16:
        return "vec128_t";
    default:
        return "uint64_t";
    }
}

std::string zero(const std::string &r)
{
    if (r == "wzr" || r == "xzr")
        return "0";
    return r;
}

std::string add_const(const std::string &addr, uint64_t step)
{
    char b[32];
    snprintf(b, sizeof b, " + 0x%llx", (unsigned long long)step);
    return addr + b;
}

std::string imm(const std::string &in)
{
    return (!in.empty() && in[0] == '#') ? in.substr(1) : in;
}

std::string rename_regs(const std::string &in)
{
    std::string out;
    for (size_t i = 0; i < in.size();)
    {
        const char c = in[i];
        const bool cand = (c == 'x' || c == 'w') && i + 1 < in.size() && in[i + 1] >= '0' &&
                          in[i + 1] <= '9';
        const bool prev_ok = i == 0 || !(isalnum((unsigned char)in[i - 1]) || in[i - 1] == '_');
        if (cand && prev_ok)
        {
            size_t j = i + 1;
            while (j < in.size() && in[j] >= '0' && in[j] <= '9')
                j++;
            const int r = atoi(in.substr(i + 1, j - i - 1).c_str());
            if (r < 32)
            {
                out += pv(r, c == 'w');
                i = j;
                continue;
            }
        }
        out.push_back(c);
        i++;
    }
    return out;
}

std::string mnemonic(const Insn &in)
{
    const size_t sp = in.text.find(' ');
    return sp == std::string::npos ? in.text : in.text.substr(0, sp);
}

std::string operands(const Insn &in)
{
    const size_t sp = in.text.find(' ');
    return sp == std::string::npos ? std::string() : in.text.substr(sp + 1);
}

void split_ops(const std::string &src, std::vector<std::string> &out)
{
    int depth = 0;
    std::string cur;
    for (size_t i = 0; i < src.size(); i++)
    {
        const char c = src[i];
        if (c == '[')
            depth++;
        else if (c == ']')
            depth--;
        if (c == ',' && depth == 0)
        {
            while (!cur.empty() && cur[0] == ' ')
                cur.erase(cur.begin());
            while (!cur.empty() && cur[cur.size() - 1] == ' ')
                cur.erase(cur.size() - 1);
            out.push_back(cur);
            cur.clear();
            continue;
        }
        cur.push_back(c);
    }
    while (!cur.empty() && cur[0] == ' ')
        cur.erase(cur.begin());
    while (!cur.empty() && cur[cur.size() - 1] == ' ')
        cur.erase(cur.size() - 1);
    if (!cur.empty())
        out.push_back(cur);
}

std::string mem_expr(const std::string &op, const NameTable &fields, std::string &hint)
{
    const size_t br = op.find('[');
    const size_t close = op.find(']', br == std::string::npos ? 0 : br);
    int64_t off = 0;
    bool have_off = false;
    if (br == std::string::npos || close == std::string::npos)
        return op;
    const std::string inner = op.substr(br + 1, close - br - 1);
    std::vector<std::string> parts;
    split_ops(inner, parts);
    if (parts.empty())
        return op;
    const std::string base_r = parts[0];
    std::string idx;
    int idx_shift = -1;
    for (size_t i = 1; i < parts.size(); i++)
    {
        const std::string &p = parts[i];
        if (p.compare(0, 3, "lsl") == 0)
        {
            const size_t h = p.find('#');
            if (h != std::string::npos)
                idx_shift = atoi(p.c_str() + h + 1);
        }
        else if (!p.empty() && p[0] == '#')
        {
            off = strtoll(p.c_str() + 1, nullptr, 0);
            have_off = true;
        }
        else if (!p.empty() && p[0] != '[')
            idx = p;
    }
    std::string out = base_r;
    if (have_off)
    {
        char b[32];
        snprintf(b, sizeof b, off < 0 ? " - 0x%llx" : " + 0x%llx",
                 (unsigned long long)(off < 0 ? -off : off));
        out += b;
        if (off > 0 && base_r != "sp")
        {
            uint64_t delta = 0;
            (void)delta;
            const std::string *nm = fields.nearest((uint64_t)off, &delta);
            if (nm && delta == 0)
                hint = *nm + "?";
        }
    }
    if (!idx.empty())
    {
        out += " + ";
        if (idx_shift >= 0)
            out += "(" + idx + " << " + std::to_string(idx_shift) + ")";
        else
            out += idx;
    }
    return out;
}

struct Cmp
{
    bool valid = false;
    std::string a;
    std::string b;
    std::string mn;
};

std::string cond_expr(const Cmp &c, const std::string &cond)
{
    std::string A = c.valid ? imm(c.a) : std::string("fl");
    std::string B = c.valid ? imm(c.b) : std::string("0");
    const bool cmp = !c.valid || c.mn == "cmp";
    std::string op;
    if (cond == "eq")
        op = "==";
    else if (cond == "ne")
        op = "!=";
    else if (cond == "lt")
        op = "<";
    else if (cond == "le")
        op = "<=";
    else if (cond == "gt")
        op = ">";
    else if (cond == "ge")
        op = ">=";
    else if (cond == "hi")
        op = "(uint64_t)" + A + " > " + B;
    else if (cond == "ls")
        op = "(uint64_t)" + A + " <= " + B;
    else if (cond == "cs")
        op = "(uint64_t)" + A + " >= " + B;
    else if (cond == "cc")
        op = "(uint64_t)" + A + " < " + B;
    else if (cond == "mi")
        op = A + " < 0";
    else if (cond == "pl")
        op = A + " >= 0";
    else
        return "fl";
    if (!cmp)
        return A + " " + op + " " + B + " /* cmn */";
    return A + " " + op + " " + B;
}

} // namespace

std::string pseudo_function(const Func &f, uint64_t base, const NameTable &names,
                            const NameTable &fields, const char *title, size_t max_lines)
{
    std::string out;
    std::set<uint64_t> leaders;
    std::map<uint64_t, std::string> labels;
    bool used[32] = {false};
    Cmp last_cmp;
    int li = 0;

    leaders.insert(f.start);
    for (size_t i = 0; i < f.insns.size(); i++)
    {
        const Insn &in = f.insns[i];
        if ((in.kind == IK_BRANCH || in.kind == IK_CALL) && in.target >= f.start && in.target < f.end)
            leaders.insert(in.target);
        if ((in.kind == IK_BRANCH || in.kind == IK_RET) && i + 1 < f.insns.size())
            leaders.insert(f.insns[i + 1].va);
    }
    for (std::set<uint64_t>::iterator it = leaders.begin(); it != leaders.end(); ++it)
    {
        if (*it == f.start)
            continue;
        char b[24];
        snprintf(b, sizeof b, "L%d", li++);
        labels[*it] = b;
    }

    for (size_t i = 0; i < f.insns.size(); i++)
    {
        const Insn &in = f.insns[i];
        const std::string mn = mnemonic(in);
        std::vector<std::string> part;
        split_ops(operands(in), part);
        std::string line;

        if (labels.count(in.va))
        {
            out += labels[in.va] + ":\n";
        }
        if (out.size() > max_lines * 64)
        {
            out += "// -- cut: pseudocode line cap --\n";
            break;
        }

        const bool is_load = mn.compare(0, 3, "ldr") == 0 || mn.compare(0, 3, "ldu") == 0 ||
                             mn.compare(0, 3, "ldt") == 0 || mn.compare(0, 3, "lds") == 0 ||
                             mn == "ldr";
        const bool is_store = mn.compare(0, 3, "str") == 0 || mn.compare(0, 3, "stu") == 0 ||
                              mn.compare(0, 3, "stt") == 0;
        const bool cmp_like = (mn == "cmp" || mn == "cmn" || mn == "tst");
        const char *op2 = nullptr;
        if (mn == "add")
            op2 = "+";
        else if (mn == "sub")
            op2 = "-";
        else if (mn == "and")
            op2 = "&";
        else if (mn == "orr")
            op2 = "|";
        else if (mn == "eor")
            op2 = "^";
        else if (mn == "mul" || mn == "madd")
            op2 = "*";
        else if (mn == "udiv" || mn == "sdiv")
            op2 = "/";

        if (in.kind == IK_RET)
        {
            line = "return " + pv(0, false) + ";";
        }
        else if (mn == "mov" && part.size() >= 2)
        {
            std::string rhs = part[1];
            if (part.size() >= 4 && part[2] == "lsl")
                rhs = "(" + part[1] + " << " + part[3].substr(1) + ")";
            line = part[0] + " = " + rhs + ";";
            used[in.rd & 31] = true;
        }
        else if ((mn == "movz" || mn == "movn" || mn == "movk") && part.size() >= 2)
        {
            line = part[0] + " = " + imm(part[1]) + ";";
            used[in.rd & 31] = true;
        }
        else if (op2 && part.size() >= 3)
        {
            const std::string r = part[2];
            if (!r.empty() && r[0] == '#')
                line = part[0] + " = " + part[1] + " " + op2 + " " + r.substr(1) + ";";
            else
                line = part[0] + " = " + part[1] + " " + op2 + " " + r + ";";
            used[in.rd & 31] = true;
        }
        else if ((mn == "lsl" || mn == "lsr" || mn == "asr" || mn == "ror") && part.size() >= 3)
        {
            const char *o = mn == "lsl" ? "<<" : mn == "lsr" ? ">>" : mn == "asr" ? ">>" : "ror";
            line = part[0] + " = " + part[1] + " " + o + " " + part[2].substr(1) + ";";
            used[in.rd & 31] = true;
        }
        else if (mn == "csel" && part.size() >= 4)
        {
            std::string c = zero(part[3]);
            if (last_cmp.valid)
            {
                c = cond_expr(last_cmp, part[3]);
                last_cmp.valid = false;
            }
            line = part[0] + " = (" + c + ") ? " + zero(part[1]) + " : " + zero(part[2]) + ";";
        }
        else if (mn == "adrp" || mn == "adr")
        {
            const std::string *nm = names.nearest(in.target - base, nullptr);
            line = part[0] + " = " + part[1] + ";";
            if (nm)
                line += "   // " + *nm;
        }
        else if (cmp_like && part.size() >= 2)
        {
            last_cmp.valid = true;
            last_cmp.mn = mn;
            last_cmp.a = part[0];
            last_cmp.b = part.size() > 1 ? part[1] : "0";
            line = "// " + in.text;
        }
        else if (mn.compare(0, 2, "b.") == 0 && in.target)
        {
            const std::string cond = mn.substr(2);
            std::string tgt = labels.count(in.target) ? labels[in.target] : "?";
            line = "if (" + cond_expr(last_cmp, cond) + ") goto " + tgt + ";";
            last_cmp.valid = false;
        }
        else if ((mn == "cbz" || mn == "cbnz" || mn == "tbz" || mn == "tbnz") && part.size() >= 2)
        {
            std::string tgt = in.target && labels.count(in.target) ? labels[in.target] : "?";
            if (mn == "cbz")
                line = "if (" + part[0] + " == 0) goto " + tgt + ";";
            else if (mn == "cbnz")
                line = "if (" + part[0] + " != 0) goto " + tgt + ";";
            else
            {
                const std::string bit = part[1].substr(1);
                line = "if (((" + part[0] + " >> " + bit + ") & 1) " +
                       (mn == "tbz" ? "== 0" : "!= 0") + ") goto " + tgt + ";";
            }
        }
        else if (mn == "b" && in.target)
        {
            line = "goto " + (labels.count(in.target) ? labels[in.target] : std::string("?")) + ";";
        }
        else if ((mn == "br" || mn == "braa") && !part.empty())
        {
            line = "goto *" + part[0] + ";";
        }
        else if (mn == "bl" && in.target)
        {
            std::string name = names.label_for(in.target - base);
            std::string args;
            for (int r = 0; r < 5; r++)
            {
                if (!used[r])
                    break;
                if (!args.empty())
                    args += ", ";
                args += pv(r, false);
            }
            line = pv(0, false) + " = " + name + "(" + args + ");";
            for (int r = 0; r < 8; r++)
                used[r] = false;
            used[0] = true;
        }
        else if ((mn == "blr" || mn == "blraa") && !part.empty())
        {
            line = pv(0, false) + " = ((" + wtype(8) + "(*)(...))" + part[0] + ")();";
        }
        else if ((mn == "ldp" || mn == "stp" || mn == "ldpsw") && part.size() >= 3)
        {
            std::string hint;
            const std::string addr = mem_expr(part[2], fields, hint);
            const std::string t = wtype(in.width);
            const std::string step = std::to_string(in.width);
            if (mn[0] == 'l')
            {
                line = part[0] + " = *(" + t + " *)(" + addr + ");\n";
                line += "    " + part[1] + " = *(" + t + " *)(" + add_const(addr, in.width) + ");";
            }
            else
            {
                line = "*(" + t + " *)(" + addr + ") = " + part[0] + ";\n";
                line += "    *(" + t + " *)(" + add_const(addr, in.width) + ") = " + part[1] + ";";
            }
            if (!hint.empty())
                line += "  // +off matches " + hint;
        }
        else if (is_load && part.size() >= 2)
        {
            std::string hint;
            const std::string src = mem_expr(part[1], fields, hint);
            std::string ty = wtype(in.width);
            if (!part[0].empty() && part[0][0] == 's')
                ty = "float";
            else if (!part[0].empty() && part[0][0] == 'd')
                ty = "double";
            else if (!part[0].empty() && part[0][0] == 'q')
                ty = "uint64_t";
            line = part[0] + " = *(" + ty + " *)(" + src + ");";
            if (!hint.empty())
                line += "  // +off matches " + hint;
        }
        else if (is_store && part.size() >= 2)
        {
            std::string hint;
            const std::string src = mem_expr(part[1], fields, hint);
            line = "*(" + wtype(in.width) + " *)(" + src + ") = " + part[0] + ";";
            if (!hint.empty())
                line += "  // +off matches " + hint;
        }
        else if (mn == "nop" || mn == "pacibsp" || mn == "paciasp" || mn == "autibsp" ||
                 mn == "autiasp" || mn == "dmb" || mn == "dsb" || mn == "isb" || mn == "sev")
        {
            line = "// " + in.text;
        }
        else if (in.kind == IK_UNKNOWN || in.kind == IK_OTHER || in.kind == IK_SYS)
        {
            line = "// " + in.text;
        }
        else
        {
            line = "// " + in.text;
        }

        out += "    " + rename_regs(line) + "\n";
    }

    std::string head = "```c\n// " + std::string(title ? title : "sub") + "  @ 0x";
    char b[32];
    snprintf(b, sizeof b, "%llx", (unsigned long long)(f.start - base));
    head += b;
    head += f.truncated ? "  (truncated)\n" : "\n";
    return head + out + "```\n";
}

} // namespace rcl
