// --------------------------------------------------
// Copyright (C) 2017 All rights reserved
// Edward T. Kaszubski <ekaszubski@gmail.com>
// --------------------------------------------------
#ifndef _WACOM_WACOMSMARTPADUTIL_H_
#define _WACOM_WACOMSMARTPADUTIL_H_

// util data structures
typedef struct
{
    size_t size;
    unsigned char * data;
} MemBlock;

typedef struct
{
    MemBlock block;
    unsigned char const * read_ptr;
} MemBlockReader;

typedef struct
{
    MemBlock block;
    unsigned char * write_ptr;
} MemBlockWriter;

void print_bytes(void const * const data, size_t size);
unsigned short read_ushort_le(void const * const data);
unsigned int read_uint_le(void const * const data);

#endif // _WACOM_WACOMSMARTPADUTIL_H_
