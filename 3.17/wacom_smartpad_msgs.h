// --------------------------------------------------
// Copyright (C) 2017 All rights reserved
// Edward T. Kaszubski <ekaszubski@gmail.com>
// --------------------------------------------------
#ifndef _WACOM_WACOMSMARTPADMSGS_H_
#define _WACOM_WACOMSMARTPADMSGS_H_

#include "wacom_smartpad_util.h"

// message data structures

// the header is the data we know will always be there for a given type
// +1 byte
typedef struct
{
    unsigned char channel;
} __attribute__((__packed__)) IP2PacketHeader;

// +3 bytes -> 4 bytes
typedef struct
{
    // 1 byte
    IP2PacketHeader packet_header;
    unsigned char skip;

    unsigned char code;
    unsigned char size;
} __attribute__((__packed__)) IP2PayloadHeader;

// +8 bytes -> 12 bytes
typedef struct
{
    // 4 bytes
    IP2PayloadHeader payload_header;
    unsigned char unix_time[6];
    unsigned char pen_type;
    unsigned char pen_id;
} __attribute__((__packed__)) IP2LiveHeader;

// +6 bytes
typedef struct
{
    // 2 bytes
    union
    {
        struct
        {
            unsigned char low;
            unsigned char high;
        } bytes;
        unsigned short raw;
    } x;
    // 2 bytes
    union
    {
        struct
        {
            unsigned char low;
            unsigned char high;
        } bytes;
        unsigned short raw;
    } y;
    // 2 bytes
    union
    {
        struct
        {
            unsigned char low;
            unsigned char high;
        } bytes;
        unsigned short raw;
    } pressure;
} __attribute__((__packed__)) IP2PaperMsg;

// +2 bytes -> 3 bytes
typedef struct
{
    // 1 byte
    IP2PacketHeader packet_header;
    // 1 byte
    union
    {
        struct
        {
            unsigned char capacity:7;
            unsigned char charging:1;
        } components;
        unsigned char raw;
    } battery_state;
    // 1 byte
    union
    {
        struct
        {
            unsigned char paper_enabled:1;
            unsigned char skip:6;
            unsigned char touch_enabled:1;
        } components;
        unsigned char raw;
    } misc_state;
} __attribute__((__packed__)) IP2StatusHeader;

// +3 bytes -> 4 bytes
typedef struct
{
    // 1 byte
    IP2PacketHeader packet_header;
    unsigned char skip;

    // 2 bytes
    union
    {
        struct
        {
            unsigned char low;
            unsigned char high;
        } bytes;
        unsigned short raw;
    } size;
} __attribute__((__packed__)) IP2FileHeader;

// +2 bytes -> 6 bytes
typedef struct
{
    // 4 bytes
    IP2PayloadHeader packet_header;

    // 2 bytes
    union
    {
        struct
        {
            unsigned char low;
            unsigned char high;
        } bytes;
        unsigned short raw;
    } num_files;
} __attribute__((__packed__)) IP2NumFilesHeader;

// +16 bytes
typedef struct
{
    // 4 bytes
    union
    {
        unsigned char bytes[4];
        unsigned int raw;
    } file_magic;

    unsigned char unix_time[6];
    // 4 bytes
    union
    {
        unsigned char bytes[4];
        unsigned int raw;
    } strokes;
    unsigned char skip[2];
} __attribute__((__packed__)) IP2FileInfoMsg;

// +1 byte -> 5 bytes
typedef struct
{
    // 4 bytes
    IP2PayloadHeader payload_header;

    unsigned char subcode;
} __attribute__((__packed__)) IP2InfoHeader;

// +10 bytes -> 14 bytes
typedef struct
{
    // 4 bytes
    IP2PayloadHeader payload_header;
    // 4 bytes
    union
    {
        unsigned char bytes[4];
        unsigned int raw;
    } file_size;
    unsigned char date_time[6];
} __attribute__((__packed__)) IP2InfoListingHeader;

// +10 bytes -> 15 bytes
typedef struct
{
    // 5 bytes
    IP2InfoHeader info_header;
    // 4 bytes
    union
    {
        unsigned char bytes[4];
        unsigned int raw;
    } file_size;
    unsigned char date_time[6];
} __attribute__((__packed__)) IP2InfoListing2Header;

// +4 bytes -> 9 bytes
typedef struct
{
    // 5 bytes
    IP2InfoHeader info_header;
    // 4 bytes
    union
    {
        unsigned char bytes[4];
        unsigned int raw;
    } checksum;
} __attribute__((__packed__)) IP2InfoChecksumHeader;

// +2 bytes
typedef struct
{
    // 2 bytes
    union
    {
        unsigned char bytes[2];
        unsigned short raw;
    } tag;
} __attribute__((__packed__)) IP2FileTagMsg;

// +16 bytes
typedef struct
{
    unsigned char tag;
    // 1 byte
    union
    {
        struct
        {
            unsigned char pen_type:6;
            unsigned char new_layer:1;
            unsigned char has_pen_id:1;
        } components;
        unsigned char raw;
    } flags;
    unsigned char date_time[6];
    unsigned char pen_id[8];
} __attribute__((__packed__)) IP2FileTagMetadataMsg;

// +8 bytes
typedef struct
{
    // 2 bytes
    IP2FileTagMsg tag;
    // 6 bytes
    IP2PaperMsg point;
} __attribute__((__packed__)) IP2FileTagStrokeMsg;

typedef struct
{
    IP2FileInfoMsg info;
    // this includes metadata and strokes
    MemBlock tag_data;
} IP2DrawingFile;

#endif // _WACOM_WACOMSMARTPADMSGS_H_
