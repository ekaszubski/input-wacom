// --------------------------------------------------
// Copyright (C) 2017 All rights reserved
// Edward T. Kaszubski <ekaszubski@gmail.com>
// --------------------------------------------------
#include <linux/kernel.h>
#include "wacom_smartpad_util.h"

// print 0x10 (16) octets per line
void print_bytes(void const * const data, size_t size)
{
    static char buf[2+0x10*5+5];

    size_t i;
    size_t j = 0;
    size_t offset = 0;
    offset += snprintf(buf + offset, sizeof(buf)-offset, "{");
    for(i = 0; i < size; ++i)
    {
        offset += snprintf(buf + offset, sizeof(buf)-offset, "0x%02x", ((unsigned char*)data)[i]);
        if(i < size - 1) offset += snprintf(buf + offset, sizeof(buf)-offset, ",");
        else snprintf(buf + offset, sizeof(buf)-offset, "}");

        if(i > 0 && (i+1) % 0x10 == 0)
        {
            j = i+1;
            pr_info("%s\n", buf);
            offset = 0;
        }
    }
    if(j < i) pr_info("%s\n", buf);
}

unsigned short read_ushort_le(void const * const data)
{
    // shortcut for LE systems
    return *(unsigned short const * const)data;
    // long way for BE systems
    //return (((unsigned char*)data)[1] << 8) | ((unsigned char*)data)[0];
}

unsigned int read_uint_le(void const * const data)
{
    // shortcut for LE systems
    return *(unsigned int const * const)data;
    // long way for BE systems
    //return (((unsigned char*)data)[3] << 24) | (((unsigned char*)data)[2] << 16) | (((unsigned char*)data)[1] << 8) | ((unsigned char*)data)[0];
}
