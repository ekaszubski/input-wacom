// --------------------------------------------------
// Copyright (C) 2017 All rights reserved
// Edward T. Kaszubski <ekaszubski@gmail.com>
// --------------------------------------------------
#include <linux/slab.h>
#include <linux/usb.h>
#include <linux/string.h>
#include "wacom_smartpad.h"

struct usb_wacom_smartpad * __wacom_dev = NULL;

static void wacom_smartpad_abort_transfers(struct usb_wacom_smartpad * wacom_dev)
{
    if(!wacom_dev) return;

    if(!wacom_dev->usb_dev) return;

    if(wacom_dev->usb_dev->state == USB_STATE_NOTATTACHED) return;

    if(wacom_dev->bulk_urb) usb_kill_urb(wacom_dev->bulk_urb);
    if(wacom_dev->ctrl_urb) usb_kill_urb(wacom_dev->ctrl_urb);
}

static void usb_wacom_smartpad_free(struct usb_wacom_smartpad * wacom_dev)
{
    if(!wacom_dev) return;

    wacom_smartpad_abort_transfers(wacom_dev);

    if(wacom_dev->bulk_urb) usb_free_urb(wacom_dev->bulk_urb);
    if(wacom_dev->ctrl_urb) usb_free_urb(wacom_dev->ctrl_urb);

    kfree(wacom_dev->bulk_buffer);
    kfree(wacom_dev->ctrl_buffer);
    kfree(wacom_dev->ctrl_request);
    kfree(wacom_dev);
}

static int wacom_smartpad_send_ctrl(struct usb_wacom_smartpad * wacom_dev, struct smartpad_cmd * cmd)
{
    unsigned char buf[] = { 0x01, 0x00, cmd->command, 0x01, cmd->state };

    pr_info("smartpad: send_ctrl command 0x%02x state 0x%02x\n", cmd->command, cmd->state);

    return usb_control_msg(
        wacom_dev->usb_dev,
        // we always send on endpoint 0
        usb_sndctrlpipe(wacom_dev->usb_dev, 0x00),
        wacom_dev->ctrl_request->bRequest,
        wacom_dev->ctrl_request->bRequestType,
        wacom_dev->ctrl_request->wValue,
        wacom_dev->ctrl_request->wIndex,
        buf,
        sizeof(buf),
        HZ * 5);
}

static unsigned char get_buffer_idx(size_t shifts, size_t idx)
{
    static unsigned char buffer_idxs[3] = { 0, 4, 8 };

    // 0, 0 -> 0
    // 1, 0 -> 2
    // 2, 0 -> 1
    // 3, 0 -> 0

    // 0, 0 -> 0
    // 0, 1 -> 1
    // 0, 2 -> 2

    // 1, 0 -> 2
    // 1, 1 -> 0
    // 1, 2 -> 1

    // 2, 0 -> 1
    // 2, 1 -> 2
    // 2, 2 -> 0

    size_t const idx_offset = ((3-(shifts % 3))+idx)%3;

    return buffer_idxs[idx_offset];
}

// reader : reader for compressed data
// block : mem block to decompress to
static MemBlock wacom_smartpad_decompress(MemBlockReader reader, MemBlock block)
{
    MemBlockWriter writer =
    {
        .block = block,
        .write_ptr = block.data
    };

    unsigned short work_buffer[12] = {0};
    unsigned short predict[4] = {0};

    size_t i;
    size_t shifts = 0;

    pr_info("decompressing from %lu bytes of data\n", reader.block.size);

    //print_bytes(reader.read_ptr, reader.block.size - (reader.read_ptr - reader.block.data));

    if(!writer.block.size)
    {
        pr_info("alloc %lu bytes for decompressed data\n", 5 * reader.block.size);
        writer.block.size = 5 * reader.block.size;
        writer.block.data = kmalloc(writer.block.size, GFP_KERNEL);
        writer.write_ptr = writer.block.data;
    }

    while(reader.read_ptr < reader.block.data + reader.block.size)
    {
        unsigned char tag = *(reader.read_ptr++);

//        pr_info("output from chunk %u\n", get_buffer_idx(shifts,0)/4);

        // predict[i] = 2 * (i-th short of 2rd chunk of work buffer) - (i-th short of 3rd chunk of work buffer)
        // on first iteration, work buffer is all zero, so all predicts are 0x0000
        // on next iteration, the buffer is shifted right, so the 2nd buffer chunk is the previous output chunk, and the 3rd buffer chunk is zero,
        // unless a 16-bit value was encoded, in which case this evaluates to 2x-x=x; so in a 16-byte scenario, predict[i] = work buffer[i]
        // on i-th iteration, the, the 2nd buffer chunk is the previous output chunk, and the 3rd buffer chunk is the output chunk from two iterations ago
        // thus, the next predict is 2 * previous output - previous previous output, or the last 16-bit input value
        for(i = 0; i < 4; ++i)
        {
            predict[i] = 2 * work_buffer[i + get_buffer_idx(shifts, 1)] - work_buffer[i + get_buffer_idx(shifts, 2)];
//            pr_info("predict %lu = 0x%04x\n", i, predict[i]);
        }

        for(i = 0; i < 4; ++i)
        {
            unsigned short diff = 0;

            // read a byte; interpret the 4 sets of 2 bits as four different values (range [0-3])
            switch((tag >> i * 2) & 0x03)
            {
            case 0: // no data
            case 1: // not implemented
                // i-th short of diff is empty (0x0000)
                // i-th short of first chunk of work buffer = i-th short of predict
                // on first iteration, predict is empty (0x0000) so this will put a 0x0000 into the i-th short of the first chunk of the work buffer
                // these consume no input data and simply set the i-th short of the output chunk of the working buffer to the i-th predict
                work_buffer[i + get_buffer_idx(shifts, 0)] = predict[i];
//                pr_info("set chunk %u:%lu via predict 0x%04x\n", get_buffer_idx(shifts, 0)/4, i, work_buffer[i + get_buffer_idx(shifts, 0)]);
                break;
            case 2: // 8 bits
                // i-th short of diff is the next data byte
                diff = *(reader.read_ptr++);
                // i-th short of first chunk of work buffer = i-th predict + i-th diff = i-th predict + next data byte
                // on first iteration, i-th predict is 0x0000, so i-th short of first chunk of work buffer is just the next data byte
                work_buffer[i + get_buffer_idx(shifts, 0)] = predict[i] + (char)diff;
//                pr_info("set chunk %u:%lu via predict %u + diff %i : %u\n", get_buffer_idx(shifts, 0)/4, i, predict[i], (char)diff, work_buffer[i + get_buffer_idx(shifts, 0)]);
                break;
            case 3: // 16 bits
                // i-th short of diff is the next two data bytes (short is encoded LSB,MSB)
                diff = read_ushort_le(reader.read_ptr);
//                diff = (reader.read_ptr[1] << 8) | reader.read_ptr[0];
//                pr_info("fill chunk *:%lu with 0x%04x\n", i, diff);
                reader.read_ptr += 2;
                // fill the i-th byte of all chunks of the work buffer with the next two data bytes
                work_buffer[i + get_buffer_idx(shifts, 2)] = diff;
                work_buffer[i + get_buffer_idx(shifts, 1)] = diff;
                work_buffer[i + get_buffer_idx(shifts, 0)] = diff;
                break;
            }
        }

        // the first chunk of the work buffer encodes 8 bytes in 4 shorts
        // every 8 output bytes is a new IP2FileTagStroke (2 tag bytes + 6 paper msg bytes)
        // thus each iteration we are producing a new IP2FileTagStroke
        for(i = 0; i < 4; ++i)
        {
            // the next two bytes of output are the the i-th short of the first chunk of the work buffer (short is decoded LSB,MSB)

            // shortcut for LE systems
            *(unsigned short*)writer.write_ptr = work_buffer[i + get_buffer_idx(shifts, 0)];
            writer.write_ptr += 2;
            // long way for BE systems
//            *(writer.write_ptr++) = work_buffer[i + get_buffer_idx(shifts, 0)] & 0xff;
//            *(writer.write_ptr++) = (work_buffer[i + get_buffer_idx(shifts, 0)] >> 8) & 0xff;
        }

        // we shift the work buffer chunks every 8 output bytes / 4 output shorts
        ++shifts;
    }

    writer.block.size = writer.write_ptr - writer.block.data;

    pr_info("decompressed %lu bytes\n", writer.block.size);

    //print_bytes(writer.block.data, writer.block.size);

    return writer.block;
}

//static void wacom_smartpad_parse_drawing_stroke(MemBlockReader * reader)
//{
//    IP2FileTagStrokeMsg * stroke = (IP2FileTagStrokeMsg*)reader->read_ptr;
//
//    if(stroke->point.x.raw == 0xffff && stroke->point.y.raw == 0xffff && stroke->point.pressure.raw == 0xffff) pr_info("stroke end\n");
//    else pr_info("x: %u, y: %u, pressure: %u\n", read_ushort_le(&stroke->point.x.raw), read_ushort_le(&stroke->point.y.raw), read_ushort_le(&stroke->point.pressure.raw));
//
////    print_bytes(reader.read_ptr, 8);
//
//    reader->read_ptr += 8;
//}
//
//static size_t wacom_smartpad_parse_drawing_metadata(MemBlockReader * reader)
//{
//    IP2FileTagMetadataMsg * meta = (IP2FileTagMetadataMsg*)reader->read_ptr;
//
//    pr_info("new stroke; pen type: 0x%02x\n", meta->flags.components.pen_type);
//    if(meta->flags.components.new_layer) pr_info("new layer\n");
//
//    reader->read_ptr += 8;
//
//    if(meta->flags.components.has_pen_id)
//    {
//        //pr_info("pen id: 0x%04x%04x\n", read_uint_le(meta->pen_id), read_uint_le(meta->pen_id + 4));
//        pr_info("pen id: ");
//        print_bytes(meta->pen_id, 8);
//        reader->read_ptr += 8;
//        return 1;
//    }
//    return 0;
//}
//
//static void wacom_smartpad_parse_drawing(MemBlockReader reader)
//{
//    size_t num_msgs = reader.block.size / 8;
//
//    pr_info("parsing drawing file containing %lu messages\n", num_msgs);
//
//    while(reader.read_ptr < reader.block.data + reader.block.size)
//    {
////        pr_info("%lu: ", offset / 8);
////        print_bytes(reader.read_ptr, 8);
//        unsigned char tag = ((IP2FileTagMsg*)reader.read_ptr)->tag.bytes[0];
//        switch(tag)
//        {
//        case FILETAG_STROKEPOINT:
//            wacom_smartpad_parse_drawing_stroke(&reader);
//            break;
//        case FILETAG_METADATA:
//            wacom_smartpad_parse_drawing_metadata(&reader);
//            break;
//        case FILETAG_LOSTPOINTS:
//            pr_info("lost points marker\n");
//            reader.read_ptr += 8;
//            break;
//        default:
//            pr_info("unknown tag 0x%02x\n", tag);
//            reader.read_ptr += 8;
//        }
//    }
//}
//
//static IP2DrawingFile wacom_smartpad_parse_drawing_file(MemBlockReader reader)
//{
//    MemBlockWriter writer;
//
//    IP2DrawingFile result =
//    {
//        .info = {0},
//        .tag_data = {0}
//    };
//
//    IP2FileInfoMsg * info = (IP2FileInfoMsg*)reader.read_ptr;
//    pr_info("decoding drawing file\n");
//    if(read_uint_le(&info->file_magic.raw) == 0x65698267)
//    {
//        pr_info("file is in new format\n");
//        pr_info("file contains %u strokes\n", read_ushort_le(&info->strokes.raw));
//        // copy the info message
//        memcpy(&result.info, info, sizeof(IP2FileInfoMsg));
//        reader.read_ptr += sizeof(IP2FileInfoMsg);
//
//        // decompress the rest of the message
//        result.tag_data = decompress(reader, result.tag_data);
////        print_bytes(result.tag_data.data, result.tag_data.size);
//        wacom_smartpad_parse_drawing((MemBlockReader){ result.tag_data, result.tag_data.data });
//    }
//    else if(read_uint_le(&info->file_magic.raw) == 0x74623862)
//    {
//        pr_info("file is in old format\n");
//    }
//
//    return result;
//}
//
//static int wacom_smartpad_parse_packet_file(MemBlockReader reader)
//{
//    static MemBlockWriter writer = {0};
//    unsigned char * realloc_tmp;
//    unsigned int file_size;
//    static FileTransferState transfer_state = FILETRANSFERSTATE_NOT_STARTED;
//    IP2DrawingFile drawing_file;
//
//    unsigned short payload_size;
//
//    switch(((IP2PacketHeader*)reader.read_ptr)->channel)
//    {
//    case SMARTPAD_PACKETTYPE_STATE:
////        pr_info("state packet\n");
//        switch(((IP2PayloadHeader*)reader.read_ptr)->code)
//        {
//        case SMARTPAD_RSP_FILEUPLOADSTARTED:
////            pr_info("file transfer meta payload\n");
//            switch(((IP2InfoHeader*)reader.read_ptr)->subcode)
//            {
//            case SMARTPAD_RSP_FILEUPLOAD_INFO:
////                pr_info("file transfer meta: listing2\n");
//                pr_info("file transfer start\n");
//                transfer_state = FILETRANSFERSTATE_STARTED;
//                return 1;
//            case SMARTPAD_RSP_FILEUPLOAD_CHECKSUM:
////                pr_info("file transfer meta: checksum\n");
//                pr_info("file transfer end\n");
//                transfer_state = FILETRANSFERSTATE_COMPLETED;
//
//                drawing_file = wacom_smartpad_parse_drawing_file((MemBlockReader){ writer.block, writer.block.data });
//                free(writer.block.data);
//                free(drawing_file.tag_data.data);
//                return 0;
//            }
//            return 0;
//        // compressed file listing; (re)alloc space for the compressed file
//        case SMARTPAD_RSP_FILEINFO:
////            pr_info("file info listing payload\n");
//            // the info listing's size includes the size of the file start header, minus the size of the file header
//            file_size = read_uint_le(&((IP2InfoListingHeader*)reader.read_ptr)->file_size.raw);
//            pr_info("file size: %u\n", file_size);
//            // if we can alloc/realloc enough bytes for the compressed buffer
//            if((realloc_tmp = krealloc(writer.block.data, file_size, GFP_KERNEL)))
//            {
//                // the new pointer will encapsulate the old and new memory
//                // and the old memory doesn't need to be freed
//                writer.block.data = realloc_tmp;
//                writer.block.size = file_size;
//                writer.write_ptr = writer.block.data;
//            }
//            return 0;
//        case SMARTPAD_RSP_STATUS:
//            pr_info("state\n");
//            if(((IP2InfoHeader*)reader.read_ptr)->subcode == 0x00)
//            {
//                pr_info("success\n");
//            }
//            else
//            {
//                pr_info("fail\n");
//            }
//            return 0;
//        }
//        break;
//    case SMARTPAD_PACKETTYPE_FILE:
////        pr_info("file packet\n");
//        // if the transfer hasn't started, bail
//        if(transfer_state != FILETRANSFERSTATE_STARTED) break;
//        // read the payload size
//        payload_size = read_ushort_le(&((IP2FileHeader*)reader.read_ptr)->size.raw);
//        // advance the read pointer to the end of the IP2FileHeader
//        reader.read_ptr += sizeof(IP2FileHeader);
////        pr_info("payload size: %u\n", payload_size);
//        // copy the compressed chunk into the buffer
//        memcpy(writer.write_ptr, reader.read_ptr, payload_size);
//        // advance the write pointer to the end of the chunk
//        writer.write_ptr += payload_size;
//        return 1;
//    }
//
//    //print_bytes(&result->data, result->size);
//    return 0;
//}
//
//static int wacom_smartpad_parse_packet_live(MemBlockReader reader)
//{
//    pr_info("live\n");
//    return 0;
//}
//
//static int wacom_smartpad_parse_packet_status(MemBlockReader reader)
//{
//    pr_info("status\n");
//    return 0;
//}
//
//static int wacom_smartpad_process_packet(MemBlockReader reader)
//{
//    switch(((IP2PacketHeader*)reader.read_ptr)->channel)
//    {
//    case SMARTPAD_PACKETTYPE_LIVE:
//        return wacom_smartpad_parse_packet_live(reader);
//    case SMARTPAD_PACKETTYPE_STATE:
//    case SMARTPAD_PACKETTYPE_FILE:
//        return wacom_smartpad_parse_packet_file(reader);
//    case SMARTPAD_PACKETTYPE_STATUS:
//        return wacom_smartpad_parse_packet_status(reader);
//    }
//
//    return 0;
//}

int wacom_smartpad_check_response(MemBlock const * mem_block, struct smartpad_rsp const * const rsp)
{
    pr_info("smartpad: check_response\n");

    // response size 0 means don't do any checks
    if(rsp->size == 0) return 0;

    if(IS_ERR_OR_NULL(mem_block))
    {
        pr_info("empty mem block");
        return -EMSGSIZE;
    }

    //print_bytes(mem_block->data, mem_block->size);

    //pr_info("desired response data: channel 0x%02x code 0x%02x size 0x%02x\n", rsp->channel, rsp->code, rsp->size);

    // verify min size to decode channel, code, and length
    if(mem_block->size < rsp->size)
    {
        pr_info("mem block too small\n");
        return -EMSGSIZE;
    }
    // verify channel
    if(((IP2PacketHeader*)mem_block->data)->channel != rsp->channel)
    {
        pr_info("wrong channel\n");
        return -ENOMSG;
    }

    // don't verify code or size for RSP_NONE
    if(rsp->code != SMARTPAD_RSP_NONE)
    {
        // verify code
        if(((IP2PayloadHeader*)mem_block->data)->code != rsp->code)
        {
            pr_info("wrong code\n");
            return -ENOMSG;
        }
        // verify size
        if(((IP2PayloadHeader*)mem_block->data)->size < rsp->size - sizeof(IP2PayloadHeader))
        {
            pr_info("message too short\n");
            return -EMSGSIZE;
        }
    }
    return 0;
}

// returns a pointer to the relevant data
// negative attempts = try forever
void * wacom_smartpad_process_bulk(struct usb_wacom_smartpad * wacom_dev, struct smartpad_rsp const * const rsp, int attempts)
{
    int read_result;
    int bytes_transferred;

    //pr_info("smartpad: process_bulk\n");

    for(; !IS_ERR_VALUE((read_result = usb_bulk_msg(
        wacom_dev->usb_dev,
        usb_rcvbulkpipe(wacom_dev->usb_dev, wacom_dev->endpoint_descriptor->bEndpointAddress & USB_ENDPOINT_NUMBER_MASK),
        wacom_dev->bulk_buffer,
        WACOM_PKGLEN_SMARTPAD,
        &bytes_transferred,
        HZ * 5))) && bytes_transferred > 0 && attempts != 0; attempts -= (attempts > 0 ? 1 : 0))
    {
        pr_info("smartpad: process_bulk: rcv %i\n", bytes_transferred);
        // verify we got the response that we care about; if not, try again
        if(IS_ERR_VALUE(wacom_smartpad_check_response(&((MemBlock){ bytes_transferred, wacom_dev->bulk_buffer }), rsp)))
        {
            pr_info("smartpad: process_bulk: response check failed\n");
            continue;
        }

        // if we verified the response then we're good to go
        //pr_info("smartpad: process_bulk: response verified\n");
        return wacom_dev->bulk_buffer;
//        // interpret the packet, update state, and determine whether we need to keep waiting for data from the tablet
//        if(!wacom_smartpad_process_packet((MemBlockReader){ { bytes_read, wacom_dev->bulk_buffer }, wacom_dev->bulk_buffer })) break;
    }

    pr_info("timed out\n");

    // if we got here then we timed out
    return ERR_PTR(-ETIMEDOUT);
}

#define wacom_smartpad_communicate_nostate(dev, cmd, value, channel, rsp, type, retries, result)\
    if(!IS_ERR((result = ERR_PTR(wacom_smartpad_send_ctrl(dev, &((struct smartpad_cmd){ cmd, value }))))))\
        result = wacom_smartpad_process_bulk(wacom_dev, &((struct smartpad_rsp){ channel, rsp, sizeof(type) }), retries)

#define wacom_smartpad_communicate_value(dev, state, cmd, value, channel, rsp, type, retries, result)\
    if(IS_ERR(wacom_smartpad_set_state(dev, state))) result = ERR_PTR(-ENODEV);\
    else wacom_smartpad_communicate_nostate(dev, cmd, value, channel, rsp, type, retries, result)

#define wacom_smartpad_communicate(dev, state, cmd, channel, rsp, type, retries, result)\
    wacom_smartpad_communicate_value(dev, state, cmd, 0x00, channel, rsp, type, retries, result)

IP2InfoHeader * wacom_smartpad_set_state(struct usb_wacom_smartpad * wacom_dev, SmartpadState state)
{
    IP2InfoHeader * result;

    //pr_info("smartpad: set_state\n");

    if(!wacom_dev) return ERR_PTR(-ENODEV);

    if(wacom_dev->state == state)
    {
        pr_info("smartpad: set_state: saved state matches desired state\n");
        return NULL;
    }

    wacom_smartpad_communicate_nostate(
        wacom_dev,
        SMARTPAD_CMD_SETSTATE,
        state,
        SMARTPAD_CHANNEL_STATE,
        SMARTPAD_RSP_STATUS,
        IP2InfoHeader,
        3,
        result);

    // verify that the state was changed
    if(!IS_ERR(result))
    {
        if(result->subcode == SMARTPADSTATUSCODE_ACK)
        {
            pr_info("smartpad: set_state: result: %u\n", result->subcode);
            wacom_dev->state = state;
        }
        else
        {
            pr_info("smartpad: set_state: result: err: 0x%02x\n", result->subcode);
            return ERR_PTR(-EIO);
        }
    }
    else pr_info("smartpad: set_state: result: err: %li\n", PTR_ERR(result));

    return result;
}

IP2InfoListingHeader * wacom_smartpad_get_file_info(struct usb_wacom_smartpad * wacom_dev)
{
    IP2InfoListingHeader * result = NULL;

    //pr_info("smartpad: get_file_info\n");

    if(!wacom_dev) return ERR_PTR(-ENODEV);

    wacom_smartpad_communicate(
        wacom_dev,
        SMARTPADSTATE_FILETRANSFER,
        SMARTPAD_CMD_GETFILEINFO,
        SMARTPAD_CHANNEL_STATE,
        SMARTPAD_RSP_FILEINFO,
        IP2InfoListingHeader,
        3,
        result);

    if(!IS_ERR_OR_NULL(result)) pr_info("smartpad: get_file_info: result: %u\n", read_uint_le(&result->file_size.raw));
    else pr_info("smartpad: get_file_info: result: err: %li\n", PTR_ERR(result));

    return result;
}

IP2NumFilesHeader * wacom_smartpad_get_num_files(struct usb_wacom_smartpad * wacom_dev)
{
    IP2NumFilesHeader * result = NULL;

    //pr_info("smartpad: get_num_files\n");

    if(!wacom_dev) return ERR_PTR(-ENODEV);

    wacom_smartpad_communicate(
        wacom_dev,
        SMARTPADSTATE_FILETRANSFER,
        SMARTPAD_CMD_GETFILESCOUNT,
        SMARTPAD_CHANNEL_STATE,
        SMARTPAD_RSP_FILESCOUNT,
        IP2NumFilesHeader,
        3,
        result);

    if(!IS_ERR_OR_NULL(result)) pr_info("smartpad: get_num_files: result: %u\n", read_ushort_le(&result->num_files.raw));
    else pr_info("smartpad: get_num_files: result: err: %li\n", PTR_ERR(result));

    return result;
}

IP2DrawingFile * wacom_smartpad_get_file(struct usb_wacom_smartpad * wacom_dev, loff_t size)
{
    MemBlock compressed_mem_block = { 0 };
    IP2DrawingFile * drawing_file = NULL;
    IP2InfoListing2Header * listing_header = NULL;
    MemBlock file_chunk = {0};
    MemBlockWriter writer;

    pr_info("smartpad: get_file\n");

    if(!wacom_dev) return ERR_PTR(-ENODEV);

    // verify that the file has started downloading
    wacom_smartpad_communicate(
        wacom_dev,
        SMARTPADSTATE_FILETRANSFER,
        SMARTPAD_CMD_DOWNLOADOLDESTFILE,
        SMARTPAD_CHANNEL_STATE,
        SMARTPAD_RSP_FILEUPLOADSTARTED,
        IP2InfoListing2Header,
        3,
        listing_header);

    if(IS_ERR_OR_NULL(listing_header)) return (void*)listing_header;
    else
    {
        // grab any valid transfer
        while(!IS_ERR((file_chunk.data = wacom_smartpad_process_bulk(wacom_dev, &((struct smartpad_rsp){ 0 }), 3))))
        {
            //pr_info("got transfer\n");
            switch(((IP2PacketHeader*)file_chunk.data)->channel)
            {
            // file transfer, add chunk
            case SMARTPAD_CHANNEL_FILE:
                //pr_info("file chunk\n");
                if((file_chunk.size = read_ushort_le(&((IP2FileHeader*)file_chunk.data)->size.raw)) > 0)
                {
                    //pr_info("chunk size %lu\n", file_chunk.size);
                    //print_bytes(file_chunk.data, file_chunk.size + sizeof(IP2FileHeader));
                    if(!compressed_mem_block.size)
                    {
                        // if we grabbed the first transfer, allocate space for it
                        compressed_mem_block.data = kmalloc(size, GFP_KERNEL);
                        compressed_mem_block.size = size;
                        // allocate the drawing file struct and save the file header
                        drawing_file = kmalloc(sizeof(IP2DrawingFile), GFP_KERNEL);
                        drawing_file->info = *(IP2FileInfoMsg*)(file_chunk.data + sizeof(IP2FileHeader));

                        writer.block = compressed_mem_block;
                        writer.write_ptr = compressed_mem_block.data;
                    }

                    //pr_info("memcpy file chunk\n");
                    memcpy(writer.write_ptr, file_chunk.data + sizeof(IP2FileHeader), file_chunk.size);
                    writer.write_ptr += file_chunk.size;
                }
                else
                {
                    pr_info("invalid chunk size\n");
                    file_chunk.data = ERR_PTR(-EMSGSIZE);
                    goto error;
                }
                break;
            // state, look for checksum and decompress
            case SMARTPAD_CHANNEL_STATE:
                //pr_info("transfer on state channel\n");
                if(((IP2PayloadHeader*)file_chunk.data)->code == SMARTPAD_RSP_FILEUPLOADENDED && ((IP2InfoHeader*)file_chunk.data)->subcode == SMARTPAD_RSP_FILEUPLOAD_CHECKSUM)
                {
                    //pr_info("file checksum\n");

                    drawing_file->tag_data = wacom_smartpad_decompress((MemBlockReader){ compressed_mem_block, compressed_mem_block.data + sizeof(IP2FileInfoMsg) }, (MemBlock){ 0, NULL });

                    kfree(compressed_mem_block.data);

                    return drawing_file;
                }
                break;
            }
        }
    }

    return ERR_PTR(-ENOMSG);

error:
    kfree(compressed_mem_block.data);
    kfree(drawing_file);

    return (void*)file_chunk.data;
}

IP2InfoHeader * wacom_smartpad_del_file(struct usb_wacom_smartpad * wacom_dev)
{
    IP2InfoHeader * result = NULL;

    //pr_info("smartpad: del_file\n");

    if(!wacom_dev) return ERR_PTR(-ENODEV);

    wacom_smartpad_communicate(
        wacom_dev,
        SMARTPADSTATE_FILETRANSFER,
        SMARTPAD_CMD_DELETEOLDESTFILE,
        SMARTPAD_CHANNEL_STATE,
        SMARTPAD_RSP_STATUS,
        IP2InfoHeader,
        3,
        result);

    if(IS_ERR(result)) pr_info("smartpad: del_file: result: err: %li\n", PTR_ERR(result));
    else if(result->subcode != SMARTPADSTATUSCODE_ACK)
    {
        pr_info("smartpad: del_file: result: err: 0x%02x\n", result->subcode);
        return ERR_PTR(-EIO);
    }
    else pr_info("smartpad: del_file: result: %u\n", result->subcode);

    return result;
}

int wacom_smartpad_probe(struct usb_interface * interface, struct usb_device_id const * id)
{
    struct usb_device * usb_dev = interface_to_usbdev(interface);
    struct usb_wacom_smartpad * wacom_dev = NULL;
    struct usb_host_interface * host_interface;
    struct usb_endpoint_descriptor * endpoint_descriptor;
    int retval;
    size_t i;

    pr_info("probe\n");

    if(!usb_dev)
    {
        retval = -ENODEV;
        goto error;
    }

    wacom_dev = kzalloc(sizeof(struct usb_wacom_smartpad), GFP_KERNEL);

    if(!wacom_dev)
    {
        retval = -ENOMEM;
        goto error;
    }

    wacom_dev->usb_dev = usb_dev;
    wacom_dev->interface = interface;
    host_interface = interface->cur_altsetting;

    // locate first endpoint matching
    // - endpoint number: 2
    // - direction:       in
    // - transfer type:   bulk
    pr_info("looking for interface\n");
    for(i = 0; i < host_interface->desc.bNumEndpoints; ++i)
    {
        endpoint_descriptor = &host_interface->endpoint[i].desc;

        if(
            (endpoint_descriptor->bEndpointAddress & USB_ENDPOINT_NUMBER_MASK) == 0x02 &&
            (endpoint_descriptor->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == USB_DIR_IN &&
            (endpoint_descriptor->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_BULK
        )
        {
            pr_info("found interface\n");
            wacom_dev->endpoint_descriptor = endpoint_descriptor;
            break;
        }
    }

    // no matching endpoint found
    if(!wacom_dev->endpoint_descriptor)
    {
        pr_info("no interface found\n");
        retval = -ENODEV;
        goto error;
    }

    // bulk transfer setup
    if(!(wacom_dev->bulk_buffer = kmalloc(WACOM_PKGLEN_SMARTPAD, GFP_KERNEL)))
    {
        retval = -ENOMEM;
        goto error;
    }
    if(!(wacom_dev->bulk_urb = usb_alloc_urb(0, GFP_KERNEL)))
    {
        retval = -ENOMEM;
        goto error;
    }

    // control transfer setup
    if(!(wacom_dev->ctrl_buffer = kzalloc(SMARTPAD_CTRL_BUFFERSIZE, GFP_KERNEL)))
    {
        retval = -ENOMEM;
        goto error;
    }
    if(!(wacom_dev->ctrl_urb = usb_alloc_urb(0, GFP_KERNEL)))
    {
        retval = -ENOMEM;
        goto error;
    }
    if(!(wacom_dev->ctrl_request = kmalloc(sizeof(struct usb_ctrlrequest), GFP_KERNEL)))
    {
        retval = -ENOMEM;
        goto error;
    }
    // all urb requests we care about share these attributes
    wacom_dev->ctrl_request->bRequest = SMARTPAD_CTRL_REQUEST;
    wacom_dev->ctrl_request->bRequestType = SMARTPAD_CTRL_REQUEST_TYPE;
    // observed during usb snooping
    wacom_dev->ctrl_request->wValue = 0;
    wacom_dev->ctrl_request->wIndex = 0;
    wacom_dev->ctrl_request->wLength = 5;

    // we assume the tablet is in ready mode
    wacom_dev->state = SMARTPADSTATE_READY;

//    usb_fill_control_urb(
//        wacom_dev->ctrl_urb,
//        wacom_dev->usb_device,
//        usb_sndctrlpipe(wacom_dev->usb_dev, 0),
//        (unsigned char*)wacom_dev->ctrl_request,
//        wacom_dev->ctrl_buffer,
//        SMARTPAD_CTRL_BUFFERSIZE,
//        wacom_smartpad_ctrl_cb,
//        wacom_dev);

    pr_info("global wacom_dev set\n");
    usb_set_intfdata(interface, wacom_dev);
    __wacom_dev = wacom_dev;

//    if(!(retval = usb_register_dev(interface, &wacom_smartpad_class)))
//    {
//        usb_set_intfdata(interface, NULL);
//        goto error;
//    }

    return retval;

error:
    usb_wacom_smartpad_free(wacom_dev);
    return retval;
}

void wacom_smartpad_disconnect(struct usb_interface * interface)
{
    pr_info("disconnect\n");
    usb_wacom_smartpad_free(__wacom_dev);
    __wacom_dev = NULL;
    //TODO: implement any other stuff
}
