#include "rcl_docdata.h"
#include <stdio.h>
#include <string.h>
using namespace rcl;

static void emit(const char *s)
{
    for (const char *p = s; *p; p++)
    {
        if (*p == '\x1f')
            putchar('|');
        else if (*p == '\n' || *p == '\r')
            putchar(' ');
        else if (*p == '\\')
            putchar('/');
        else
            putchar(*p);
    }
}

int main()
{
    printf("classes=%u methods=%u\n", kDocClassCount, kDocMethodCount);
    for (uint32_t i = 0; i < kDocClassCount; i++)
    {
        const DocClass &d = kDocClasses[i];
        for (uint32_t k = d.first; k < d.first + d.count && k < kDocMethodCount; k++)
        {
            const DocMethod &m = kDocMethods[k];
            printf("M\t%s\t%s\t%s\t", kDocBlob + d.name, kDocBlob + m.sig, kDocBlob + m.mangled);
            emit(kDocBlob + d.strings);
            printf("\t");
            emit(kDocBlob + m.hints);
            printf("\n");
        }
    }
    return 0;
}
