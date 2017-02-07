// --------------------------------------------------
// Copyright (C) 2017 All rights reserved
// Edward T. Kaszubski <ekaszubski@gmail.com>
// --------------------------------------------------
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/ioctl.h>
#include <asm/uaccess.h>

#include "wacom_smartpad.h"
#include "wacomfs.h"

#define MODULE_NAME "wacomfs"

MODULE_LICENSE("GPL");
MODULE_VERSION("0.1.0");
MODULE_AUTHOR("Edward T. Kaszubski <ekaszubski@gmail.com>");

extern struct usb_wacom_smartpad * __wacom_dev;

static struct usb_device_id const wacom_smartpad_ids[] =
{
    // it seems that 0x357 covers both the medium and large Intuos Pro Paper tablets
    { USB_DEVICE(USB_VENDOR_ID_WACOM, 0x357) },
    // kernel wants a null-terminated array
    { }
};
MODULE_DEVICE_TABLE(usb, wacom_smartpad_ids);

static struct usb_driver wacom_smartpad_driver =
{
    .name = "wacom_smartpad",
    .id_table = wacom_smartpad_ids,
    .probe = wacom_smartpad_probe,
    .disconnect = wacom_smartpad_disconnect
};

static struct inode * wacomfs_make_inode(struct super_block * superblock, int mode)
{
    struct inode * result = new_inode(superblock);
    if(result)
    {
        result->i_mode = mode;
        result->i_uid.val = result->i_gid.val = 0;
        result->i_blocks = 0;
        result->i_atime = result->i_mtime = result->i_ctime = CURRENT_TIME;
    }
    return result;
}

static IP2DrawingFile * wacomfs_last_drawing_file = NULL;

void wacomfs_free_last_drawing_file(void)
{
    if(!IS_ERR_OR_NULL(wacomfs_last_drawing_file))
    {
        pr_info("wacomfs: free_last_drawing_file: freeing mem block\n");
        kfree(wacomfs_last_drawing_file->tag_data.data);
        kfree(wacomfs_last_drawing_file);
        wacomfs_last_drawing_file = NULL;
    }
}

static ssize_t wacomfs_read_file(struct file * file, char * buf, size_t count, loff_t * offset)
{
    static ssize_t last_file_size = 0;
    ssize_t info_bytes_copied = 0;
    ssize_t block_bytes_copied = 0;
    loff_t offset2 = 0;

    // can only download oldest file (must have non-zero size)
    if(!file->f_inode->i_size) return -EPERM;
//    if(IS_ERR_OR_NULL(file->f_dentry->i_private)) return ERR_PTR(file->f_dentry->i_private);

    pr_info("wacomfs: read_file: get %lu at %lli\n", count, *offset);

    // if there's nothing to read, try to fetch the file
    if(IS_ERR_OR_NULL(wacomfs_last_drawing_file))
    {
        pr_info("file not yet loaded, trying now\n");
        // if fetching failed, return error code
        if(IS_ERR_OR_NULL((wacomfs_last_drawing_file = wacom_smartpad_get_file(__wacom_dev, file->f_inode->i_size))))
        {
            pr_info("failed to load file\n");
            return PTR_ERR(wacomfs_last_drawing_file);
        }
        else
        {
            // record the total file size
            last_file_size = wacomfs_last_drawing_file->tag_data.size + sizeof(IP2FileInfoMsg);
            pr_info("file loaded %lu bytes\n", last_file_size);
        }
    }

    // if we're being asked to read past the end of the file, indicate EOF
    if(*offset >= last_file_size) return 0;

    // if the offset is in the info portion, read it
    if(*offset < sizeof(IP2FileInfoMsg))
    {
        // copy the file info msg
        if(IS_ERR_VALUE((info_bytes_copied = simple_read_from_buffer(buf, count, offset, (void*)&wacomfs_last_drawing_file->info, sizeof(IP2FileInfoMsg))))) return info_bytes_copied;

        pr_info("read info %li\n", info_bytes_copied);
        //print_bytes(&wacomfs_last_drawing_file->info, sizeof(IP2FileInfoMsg));
    }

    // if the new offset is in the block portion, read it
    if(*offset >= sizeof(IP2FileInfoMsg))
    {
        // if we got here, file_block->data is necessarily defined
        // also, we've either copied the info portion of the file or have been asked to skip it
        //pr_info("copying file to userspace %lu -> %lu from %lli\n", wacomfs_last_drawing_file->tag_data.size, count, *offset);
        // try to read out the rest of the file
        offset2 = *offset - sizeof(IP2FileInfoMsg);
        //print_bytes(wacomfs_last_drawing_file->tag_data.data, wacomfs_last_drawing_file->tag_data.size);
        if(IS_ERR_VALUE((block_bytes_copied = simple_read_from_buffer(buf + info_bytes_copied, count - info_bytes_copied, &offset2, wacomfs_last_drawing_file->tag_data.data, wacomfs_last_drawing_file->tag_data.size))))
        {
            return block_bytes_copied;
        }
        pr_info("read block %li\n", block_bytes_copied);
        *offset += block_bytes_copied;
    }

    return info_bytes_copied + block_bytes_copied;
}

//static int wacomfs_open_file(struct inode * inode, struct file * file)
//{
//    pr_info("open called\n");
////    file->private_data = inode->i_private;
//    return 0;
//}

//static ssize_t wacomfs_write_file(struct file * file, char const * buf, size_t count, loff_t * offset)
//{
//    pr_info("write called %lu %lli\n", count, *offset);
//    return 0;
//}

//static int wacomfs_delete_file(struct dentry const * entry)
//{
//    pr_info("delete called\n");
//
//    return 1;
//}

//static struct dentry_operations wacomfs_dentry_ops =
//{
//    .d_delete = wacomfs_delete_file,
//};

static struct file_operations wacomfs_file_ops =
{
//    .open = wacomfs_open_file,
    .read = wacomfs_read_file,
//    .write = wacomfs_write_file
};

static struct dentry * wacomfs_create_file(struct super_block * superblock, struct dentry * dir, char const * name, short mode)
{
    struct dentry * entry = NULL;
    struct inode * inode = NULL;
    struct qstr qname;

    qname.name = name;
    qname.len = strlen(name);
    qname.hash = full_name_hash(name, qname.len);

    if(!(entry = d_alloc(dir, &qname))) goto error;
    if(!(inode = wacomfs_make_inode(superblock, S_IFREG | mode))) goto error;

    //inode->i_op = &wacomfs_inode_ops;
    //inode->i_op = &simple_dir_inode_operations;
    inode->i_fop = &wacomfs_file_ops;
//    inode->i_private = downloadable ? 0x01 : PTR_ERR(-EPERM);

//    d_set_d_op(entry, &wacomfs_dentry_ops);

    d_add(entry, inode);
    return entry;

error:
    if(entry) dput(entry);
    return NULL;
}

static struct dentry * wacomfs_create_dir(struct super_block * superblock, struct dentry * parent, char const * name)
{
    struct dentry * entry = NULL;
    struct inode * inode = NULL;
    struct qstr qname;

    qname.name = name;
    qname.len = strlen(name);
    qname.hash = full_name_hash(name, qname.len);

    if(!(entry = d_alloc(parent, &qname))) goto error;
    if(!(inode = wacomfs_make_inode(superblock, S_IFDIR | 0755))) goto error;

    //inode->i_op = &wacomfs_inode_ops;
    inode->i_op = &simple_dir_inode_operations;
    inode->i_fop = &simple_dir_operations;

//    d_set_d_op(entry, &wacomfs_dentry_ops);

    d_add(entry, inode);
    return entry;

error:
    if(entry) dput(entry);
    return NULL;
}

static int wacomfs_create_listing(struct super_block * superblock)
{
    struct dentry * root = superblock->s_root;
    struct dentry * prev_file = NULL;
    struct dentry * curr_file = NULL;
    size_t i;
    // drawing|00001|\0
    char filename[7+5+1];

    IP2NumFilesHeader * num_files_header = NULL;
    IP2InfoListingHeader * oldest_file_listing = NULL;

    unsigned short num_files = 0;

    //struct dentry * prev_file = NULL;

    if(IS_ERR_OR_NULL((num_files_header = wacom_smartpad_get_num_files(__wacom_dev)))) return PTR_ERR(num_files_header);

    if((num_files = read_ushort_le(&num_files_header->num_files.raw)) > 0)
    {
        for(i = 0; i < num_files; ++i)
        {
            snprintf(filename, sizeof(filename), "drawing%lu", i + 1);
            // last file is the special downloadable file
            if(i == num_files - 1)
            {
                if(IS_ERR_OR_NULL((oldest_file_listing = wacom_smartpad_get_file_info(__wacom_dev)))) return PTR_ERR(oldest_file_listing);
                if(IS_ERR_OR_NULL((curr_file = wacomfs_create_file(superblock, root, filename, 0444)))) return PTR_ERR(curr_file);

                curr_file->d_inode->i_size = read_uint_le(&oldest_file_listing->file_size.raw);
            }
            // other files are just there to indicate number of drawings on tablet
            // and cannot be read or modified
            else
            {
                if(IS_ERR_OR_NULL((curr_file = wacomfs_create_file(superblock, root, filename, 0000)))) return PTR_ERR(curr_file);
            }

            curr_file->d_inode->i_private = prev_file;
            prev_file = curr_file;

            pr_info("created file %s\n", filename);
        }
    }

    return 0;
}

static int wacomfs_unlink(struct inode * inode, struct dentry * entry)
{
    IP2InfoHeader * result;
    struct dentry * prev_file = entry->d_inode->i_private;
    IP2InfoListingHeader * oldest_file_listing = NULL;

    //struct super_block * superblock = entry->d_sb;
    pr_info("unlink called\n");

    // only allowed to delete the oldest file, which will be the only one with non-zero size
    if(entry->d_inode->i_size == 0) return -EPERM;

    // execute delete call to tablet
    if(IS_ERR((result = wacom_smartpad_del_file(__wacom_dev)))) return PTR_ERR(result);

    // deallocate last drawing file
    wacomfs_free_last_drawing_file();

    // remove corresponding dentry
    dput(entry);

    // check whether there's another file to update
    if(IS_ERR_OR_NULL(prev_file)) return PTR_ERR(prev_file);

    // re-query tablet for oldest file info
    if(IS_ERR((oldest_file_listing = wacom_smartpad_get_file_info(__wacom_dev)))) return PTR_ERR(oldest_file_listing);

    // update the next file's size and permissions
    prev_file->d_inode->i_size = read_uint_le(&oldest_file_listing->file_size.raw);
    prev_file->d_inode->i_mode |= 0444;

    return 0;
}

static void wacomfs_destroy_file(struct inode * inode)
{
    pr_info("destroy called\n");
}

static int wacomfs_drop_file(struct inode * inode)
{
    pr_info("drop called\n");
    return 1;
}

//static void wacomfs_put_file(struct inode * inode)
//{
//    pr_info("put called\n");
//}

static struct inode_operations wacomfs_inode_ops =
{
    .lookup = simple_lookup,
    .unlink = wacomfs_unlink
};

static struct super_operations wacomfs_super_ops =
{
    .statfs = simple_statfs,
//    .drop_inode = wacomfs_drop_file,
    .drop_inode = generic_delete_inode,
//    .destroy_inode = wacomfs_destroy_file,
//    .delete_inode = wacomfs_delete_file,
//    .put_inode = wacomfs_put_file,
};

static int wacomfs_fill_sb(struct super_block * superblock, void * data, int silent)
{
    struct inode * root;

    superblock->s_blocksize = PAGE_CACHE_SIZE;
    superblock->s_blocksize_bits = PAGE_CACHE_SHIFT;
    superblock->s_magic = WACOMFS_MAGIC;
    superblock->s_op = &wacomfs_super_ops;

    if(!(root = wacomfs_make_inode(superblock, S_IFDIR | 0755))) return -ENOMEM;

    //root->i_op = &simple_dir_inode_operations;
    root->i_op = &wacomfs_inode_ops;
    root->i_fop = &simple_dir_operations;

    if(!(superblock->s_root = d_make_root(root))) return -ENOMEM;

    return wacomfs_create_listing(superblock);
}

static struct dentry * wacomfs_mount(struct file_system_type * type, int flags, char const * dev, void * data)
{
    struct dentry * entry = mount_nodev(type, flags, data, wacomfs_fill_sb);

    if(IS_ERR(entry)) pr_err("failed to create entry\n");
    else pr_info("wacomfs entry created\n");

    return entry;
}

static void wacomfs_unmount(struct super_block * superblock)
{
    // deallocate last drawing file
    wacomfs_free_last_drawing_file();
    // deallocate all inodes
    kill_litter_super(superblock);
    pr_info("wacomfs entry removed\n");
}

static struct file_system_type wacomfs_type =
{
    .owner = THIS_MODULE,
    .name = "wacomfs",
    .mount = wacomfs_mount,
    .kill_sb = wacomfs_unmount
};

static int __init wacomfs_init(void)
{
    int result;
    if(IS_ERR_VALUE((result = register_filesystem(&wacomfs_type)))) return result;
    if(IS_ERR_VALUE((result = usb_register(&wacom_smartpad_driver)))) return result;

    return result;
}

static void __exit wacomfs_exit(void)
{
    usb_deregister(&wacom_smartpad_driver);
    unregister_filesystem(&wacomfs_type);
}

module_init(wacomfs_init);
module_exit(wacomfs_exit);
