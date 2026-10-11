// Development helper for tools/decode_check.py. Not part of the dylib build.
// Reads one hex A64 word per line on stdin and prints "<word>\t<recoil decoding>".
#include "rcl_disasm.h"

#include <stdio.h>
#include <stdlib.h>

using namespace rcl;

int main()
{
    char line[128];
    while (fgets(line, sizeof line, stdin))
    {
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p || *p == '\n' || *p == '#')
            continue;
        char *end = nullptr;
        const unsigned long long w = strtoull(p, &end, 16);
        if (end == p)
            continue;
        Insn in;
        disasm_words((uint64_t)0, (uint32_t)w, in);
        printf("%08llx\t%s\n", w, in.text.c_str());
    }
    return 0;
}
