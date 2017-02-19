// --------------------------------------------------
// Copyright (C) 2017 All rights reserved
// Edward T. Kaszubski <ekaszubski@gmail.com>
// --------------------------------------------------
#ifndef _WACOM_WACOMFS_H_
#define _WACOM_WACOMFS_H_

#define WACOMFS_MAGIC 0x7761636d
#define USB_VENDOR_ID_WACOM 0x056a

// drawing1 is always the "oldest" drawing, i.e. the one we can see and delete
// when we actually do a delete, we update drawing1's inode, and delete drawingN
// since drawing2-N are just placeholders to indicate how many drawings are available
// this will look a bit weird since the delete will be issued on drawing1 but drawingN will actually go away
struct wacomfs_sb_info
{
    // entry for oldest drawing
    struct dentry * drawing1;
    // entry for newest drawing
    struct dentry * drawingN;
    // number of files
    size_t num_files;
};

#endif // _WACOM_WACOMFS_H_
