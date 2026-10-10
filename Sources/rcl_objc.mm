#import <Foundation/Foundation.h>
#import <objc/runtime.h>

#include "rcl_objc.h"

namespace rcl
{

void objc_dump(FILE *f, uint64_t base, uint64_t vmsize)
{
    unsigned int count = 0;
    Class *classes = objc_copyClassList(&count);
    if (!classes)
    {
        fprintf(f, "- the objc runtime listed nothing\n");
        return;
    }
    fprintf(f, "| class | methods in this image | selectors |\n|-------|----------------------:|"
               "-----------|\n");
    unsigned int shown = 0;
    unsigned int inImage = 0;
    for (unsigned int i = 0; i < count && shown < 600; i++)
    {
        Class c = classes[i];
        if (!c)
        {
            continue;
        }
        unsigned int mc = 0;
        Method *ms = class_copyMethodList(c, &mc);
        unsigned int mine = 0;
        char sels[1024];
        sels[0] = 0;
        for (unsigned int k = 0; ms && k < mc; k++)
        {
            IMP imp = method_getImplementation(ms[k]);
            const uint64_t a = (uint64_t)(uintptr_t)imp;
            if (a < base || a - base >= vmsize)
            {
                continue;
            }
            mine++;
            const char *sn = sel_getName(method_getName(ms[k]));
            if (sn && sels[0] == 0)
            {
                snprintf(sels, sizeof sels, "`%s`@`0x%llx`", sn,
                         (unsigned long long)(a - base));
            }
        }
        if (ms)
        {
            free(ms);
        }
        if (!mine)
        {
            continue;
        }
        inImage += mine;
        shown++;
        fprintf(f, "| %s | %u | %s |\n", class_getName(c), mine, sels);
    }
    free(classes);
    fprintf(f, "\n- `%u` objc classes with `%u` methods inside this image\n", shown, inImage);
}

} // namespace rcl
