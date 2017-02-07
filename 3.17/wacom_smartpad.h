// --------------------------------------------------
// Copyright (C) 2017 All rights reserved
// Edward T. Kaszubski <ekaszubski@gmail.com>
// --------------------------------------------------
#ifndef _WACOM_WACOMSMARTPAD_H_
#define _WACOM_WACOMSMARTPAD_H_

#include <linux/usb.h>
#include "wacom_smartpad_msgs.h"
#include "wacom_smartpad_util.h"

// Endpoint descriptor claims the packet size is 64
// Max packet length seen in usb snooping is 260
// Wacom's InkSpace app uses a buffer of 512
#define WACOM_PKGLEN_SMARTPAD 512

#define SMARTPAD_CHANNEL_STATE  0x01
#define SMARTPAD_CHANNEL_LIVE   0x02
#define SMARTPAD_CHANNEL_FILE   0x03
#define SMARTPAD_CHANNEL_STATUS 0x13

#define SMARTPAD_CTRL_BUFFERSIZE 8
#define SMARTPAD_CTRL_REQUEST 0xf0
#define SMARTPAD_CTRL_REQUEST_TYPE 0x40

#define SMARTPAD_CMD_SETSTATE           0xb1 // -> RSP_STATUS
#define SMARTPAD_CMD_GETSTATE           0xe8 // -> RSP_DEVICESTATE
#define SMARTPAD_CMD_GETFILESCOUNT      0xc1 // -> RSP_FILESCOUNT
#define SMARTPAD_CMD_GETFILEINFO        0xcc // -> RSP_FILEINFO
#define SMARTPAD_CMD_DOWNLOADOLDESTFILE 0xc3 // -> RSP_FILEUPLOADSTARTED
                                             // -> 1 or more file chunks
                                             // -> RSP_FILEUPLOADENDED
#define SMARTPAD_CMD_DELETEOLDESTFILE   0xca // -> RSP_STATUS
#define SMARTPAD_CMD_DELETEALLFILES     0xe2 // -> RSP_STATUS

#define SMARTPAD_RSP_STATUS              0xb3
#define SMARTPAD_RSP_DEVICESTATE         0xe9
#define SMARTPAD_RSP_FILESCOUNT          0xc2
#define SMARTPAD_RSP_FILEINFO            0xcf
#define SMARTPAD_RSP_FILEUPLOADSTARTED   0xc8
#define SMARTPAD_RSP_FILEUPLOADENDED     0xc8
#define SMARTPAD_RSP_FILEUPLOAD_INFO     0xbe
#define SMARTPAD_RSP_FILEUPLOAD_CHECKSUM 0xed
#define SMARTPAD_RSP_NONE                0x00

#define SMARTPAD_EVT_STROKECHUNK             0xa1
#define SMARTPAD_EVT_STROKESTART             0xa2
#define SMARTPAD_EVT_RESETREALTIMEDATABUFFER 0xcb
#define SMARTPAD_EVT_POINTSLOST              0xa3
#define SMARTPAD_EVT_NEWLAYER                0xa6
#define SMARTPAD_EVT_DATASESSIONESTABLISHED  0xee
#define SMARTPAD_EVT_DATASESSIONTERMINATED   0x23
#define SMARTPAD_EVT_PENDETECTED             0x21

typedef enum
{
    // No error.
    SMARTPADSTATUSCODE_ACK = 0,
    // The general error code value.
    SMARTPADSTATUSCODE_GENERAL_ERROR = 1,
    // The requested operation is not supported in the peripheral’s current state.
    SMARTPADSTATUSCODE_INVALID_STATE = 2,
    // The specified parameter is read-only and cannot be modified.
    SMARTPADSTATUSCODE_READONLY_PARAM = 3,
    // The command is not supported by the device.
    SMARTPADSTATUSCODE_UNRECOGNIZED_COMMAND = 5,
    // The peripheral recognizes the central, but temporally doesn’t authorize the central, because user confirmation is expected (the peripheral is in UserConfirmation mode).
    SMARTPADSTATUSCODE_UC_IN_PROGRESS = 6,
    // The peripheral is in DataSessionReady mode, but doesn’t recognize the central and denies access.
    SMARTPADSTATUSCODE_NOT_AUTH_FOR_DSR = 7,
    // The command cannot be executed, because a file download is currently in progress.
    SMARTPADSTATUSCODE_ERROR_FILE_DOWNLOADING = 8
} SmartpadStatusCode;

typedef enum
{
    // Real time drawing mode.
    SMARTPADSTATE_REALTIME = 0,
    // File transfer mode.
    SMARTPADSTATE_FILETRANSFER = 1,
    // Ready mode.
    SMARTPADSTATE_READY = 2
} SmartpadState;

typedef enum
{
    FILETRANSFERSTATE_NOT_STARTED = 0,
    FILETRANSFERSTATE_STARTED = 1,
    FILETRANSFERSTATE_COMPLETED = 2
} FileTransferState;

struct usb_wacom_smartpad
{
    struct usb_device * usb_dev;
    struct usb_interface * interface;
    struct usb_endpoint_descriptor * endpoint_descriptor;

    char * bulk_buffer;
    struct urb * bulk_urb;

    char * ctrl_buffer;
    struct urb * ctrl_urb;
    struct usb_ctrlrequest * ctrl_request;

    SmartpadState state;
};

struct smartpad_cmd
{
    unsigned char command;
    // should only be non-zero when command is SMARTPAD_CMD_SETSTATE
    // should only be set from SmartpadState
    unsigned char state;
};

struct smartpad_rsp
{
    unsigned char channel;
    unsigned char code;
    unsigned char size;
};

//void usb_wacom_smartpad_free(struct usb_wacom_smartpad * wacom_dev);
//int wacom_smartpad_ctrl(struct usb_wacom_smartpad * wacom_dev, struct smartpad_cmd command);
int wacom_smartpad_probe(struct usb_interface * interface, struct usb_device_id const * id);
void wacom_smartpad_disconnect(struct usb_interface * interface);

int wacom_smartpad_check_response(MemBlock const * mem_block, struct smartpad_rsp const * const rsp);
void * wacom_smartpad_process_bulk(struct usb_wacom_smartpad * wacom_dev, struct smartpad_rsp const * const rsp, int attempts);
IP2InfoHeader * wacom_smartpad_set_state(struct usb_wacom_smartpad * wacom_dev, SmartpadState state);
IP2InfoListingHeader * wacom_smartpad_get_file_info(struct usb_wacom_smartpad * wacom_dev);
IP2NumFilesHeader * wacom_smartpad_get_num_files(struct usb_wacom_smartpad * wacom_dev);
IP2DrawingFile * wacom_smartpad_get_file(struct usb_wacom_smartpad * wacom_dev, loff_t size);
IP2InfoHeader * wacom_smartpad_del_file(struct usb_wacom_smartpad * wacom_dev);

#endif // _WACOM_WACOMSMARTPAD_H_
