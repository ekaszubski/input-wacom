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
        result->i_ino = ((struct wacomfs_sb_info*)superblock->s_fs_info)->num_files++;
        result->i_mode = mode;
        result->i_uid.val = result->i_gid.val = 0;
        result->i_blocks = 0;
        result->i_atime = result->i_mtime = result->i_ctime = CURRENT_TIME;
        pr_info("wacomfs: make_inode: ino %lu\n", result->i_ino);
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

static struct file_operations wacomfs_file_ops =
{
    .read = wacomfs_read_file,
};

static struct dentry * wacomfs_create_file(struct super_block * superblock, struct dentry * dir, char const * name, short mode)
{
    struct dentry * entry = NULL;
    struct inode * inode = NULL;
    struct qstr qname;

    qname.name = name;
    qname.len = strlen(name);
    qname.hash = full_name_hash(name, qname.len);

    pr_info("wacomfs: create_file: name %s\n", name);

    if(!(entry = d_alloc(dir, &qname))) goto error;
    if(!(inode = wacomfs_make_inode(superblock, S_IFREG | mode))) goto error;

    inode->i_fop = &wacomfs_file_ops;

    d_add(entry, inode);
    return entry;

error:
    if(entry) dput(entry);
    return NULL;
}

// query the tablet, update the size of drawing1
static int wacomfs_update_meta(struct super_block * superblock)
{
    struct dentry * entry = ((struct wacomfs_sb_info*)superblock->s_fs_info)->drawing1;
    struct inode * file_inode = entry ? entry->d_inode : NULL;
    IP2InfoListingHeader * oldest_file_listing = NULL;

    // nothing to update
    if(!file_inode) return 0;

    // query tablet for oldest file info
    if(IS_ERR((oldest_file_listing = wacom_smartpad_get_file_info(__wacom_dev)))) return PTR_ERR(oldest_file_listing);

    // update the next file's size (perms should have been set at creation)
    file_inode->i_size = read_uint_le(&oldest_file_listing->file_size.raw);

    pr_info("wacomfs: update_meta: size %lli\n", file_inode->i_size);

    return 0;
}

static int wacomfs_add_file(struct super_block * superblock)
{
    struct dentry * root = superblock->s_root;
    // drawing|00001|\0
    char filename[7+5+1];
    struct dentry * curr_file = NULL;

    int result;
    // num_files is really num inodes so first drawing will have idx 1 since fs root will have idx 0
    size_t drawing_idx = ((struct wacomfs_sb_info*)superblock->s_fs_info)->num_files;

    snprintf(filename, sizeof(filename), "drawing%lu", drawing_idx);
    // first file is the special downloadable file
    if(drawing_idx == 1)
    {
        // create the file
        if(IS_ERR_OR_NULL((curr_file = wacomfs_create_file(superblock, root, filename, 0444)))) return PTR_ERR(curr_file);
        // record the file in the superblock
        ((struct wacomfs_sb_info*)superblock->s_fs_info)->drawing1 = ((struct wacomfs_sb_info*)superblock->s_fs_info)->drawingN = curr_file;
        // query size info from tablet
        if(IS_ERR_VALUE((result = wacomfs_update_meta(superblock)))) return result;
    }
    // other files are just there to indicate number of drawings on tablet
    // and cannot be read or modified
    else
    {
        // create the file
        if(IS_ERR_OR_NULL((curr_file = wacomfs_create_file(superblock, root, filename, 0000)))) return PTR_ERR(curr_file);
        // new files are going to point back to the previous file to make it easier for us to handle dir listing
        curr_file->d_inode->i_private = ((struct wacomfs_sb_info*)superblock->s_fs_info)->drawingN;
        // record the file in the superblock
        ((struct wacomfs_sb_info*)superblock->s_fs_info)->drawingN = curr_file;
    }

    pr_info("added file %s\n", filename);

    return 0;
}

// delete file; this will actually delete drawingN
static int wacomfs_delete_file(struct super_block * superblock)
{
    struct dentry * entry = ((struct wacomfs_sb_info*)superblock->s_fs_info)->drawingN;
    struct inode * file_inode = entry->d_inode;
    struct dentry * prev_file = file_inode->i_private;
//    struct dentry * drawing1_copy = NULL;

    pr_info("wacomfs: delete_file: name %s\n", entry->d_name.name);

    // remove corresponding dentry
    //dput(entry);
    inode_dec_link_count(file_inode);
    // decrement global ino
    --((struct wacomfs_sb_info*)superblock->s_fs_info)->num_files;

    pr_info("wacomfs: delete_file: new global ino %lu\n", ((struct wacomfs_sb_info*)superblock->s_fs_info)->num_files);

    // if this file links to a previous file, then update drawingN
    if(prev_file)
    {
        pr_info("wacomfs: delete_file: updating drawingN with prev_file\n");
        ((struct wacomfs_sb_info*)superblock->s_fs_info)->drawingN = prev_file;

//        drawing1_copy = kzalloc(sizeof(struct dentry), GFP_KERNEL);
//        memcpy(drawing1_copy, ((struct wacomfs_sb_info*)superblock->s_fs_info)->drawing1, sizeof(struct dentry));
//        d_add(drawing1_copy, ((struct wacomfs_sb_info*)superblock->s_fs_info)->drawing1->d_inode);
    }
    // otherwise we just deleted drawingN, so set everything to null
    else
    {
        pr_info("wacomfs: delete_file: no prev_file\n");
        ((struct wacomfs_sb_info*)superblock->s_fs_info)->drawing1 = ((struct wacomfs_sb_info*)superblock->s_fs_info)->drawingN = NULL;
    }

    return 0;
}

// each time this is called, query the tablet for the number of drawings
// drawing1, the special readable drawing, will always be ino number 2
// the others will just be 2+i
static int wacomfs_list(struct file * file, struct dir_context * ctx)
{
    // file is the directory we're trying to list
    // since wacomfs is a flat structure, this can only ever be the root dir
    // so all we need to do is give a name and ino for each drawing

    // query the tablet for the number of drawings
    // if the number is different than what we remember, then look at whether we need to add or delete
    // - if add, then just add the new file
    // - if delete, then we need to update the special readable drawing
    // either way, we need to iterate through all the drawings and enter their names + inode numbers here

    size_t i;
    short new_num_files = 0;
    IP2NumFilesHeader * num_files_header = NULL;

    struct inode * file_inode = file->f_inode;
    struct super_block * superblock = file_inode->i_sb;
    struct dentry * curr_file = NULL;

    pr_info("wacomfs: list\n");

    if(IS_ERR_OR_NULL((num_files_header = wacom_smartpad_get_num_files(__wacom_dev)))) return PTR_ERR(num_files_header);

    if((new_num_files = 1 + read_ushort_le(&num_files_header->num_files.raw)) != ((struct wacomfs_sb_info*)superblock->s_fs_info)->num_files)
    {
        // add
        for(i = ((struct wacomfs_sb_info*)superblock->s_fs_info)->num_files; i < new_num_files; ++i)
        {
            wacomfs_add_file(superblock);
        }

        // delete and update
        // this should basically never happen since we are the ones controlling when files get deleted
        if(new_num_files < ((struct wacomfs_sb_info*)superblock->s_fs_info)->num_files)
        {
            wacomfs_delete_file(superblock);
            wacomfs_update_meta(superblock);
        }
    }

    pr_info("wacomfs: list: incoming pos %lli\n", ctx->pos);
    if(ctx->pos > new_num_files) return 0;

    curr_file = ((struct wacomfs_sb_info*)superblock->s_fs_info)->drawingN;

    // we need to get the name of each drawing file along with its inode number
    // in this case we're going to walk backwards from drawingN to drawing1
    for(i = ((struct wacomfs_sb_info*)superblock->s_fs_info)->num_files; i > 1; --i)
    {
        if(!curr_file) break;

        pr_info("wacomfs: list: emit %s\n", curr_file->d_name.name);

        if(!dir_emit(ctx, curr_file->d_name.name, curr_file->d_name.len, d_inode(curr_file)->i_ino, dt_type(d_inode(curr_file)))) return -ENOSPC;
        ++ctx->pos;

        curr_file = curr_file->d_inode->i_private;
    }

    return 0;
}

// just add dots and forward the rest of the work to wacomfs_list
static int wacomfs_iterate(struct file * file, struct dir_context * ctx)
{
    pr_info("wacomfs: iterate\n");
    if(!dir_emit_dots(file, ctx))
    {
        return -ENOSPC;
    }
    return wacomfs_list(file, ctx);
}

static struct file_operations wacomfs_file_dops =
{
    .open = dcache_dir_open,
    .release = dcache_dir_close,
    .llseek = dcache_dir_lseek,
    .read = generic_read_dir,
    .iterate = wacomfs_iterate,
    .fsync = noop_fsync
};

// if the newest drawing is drawing1
// - each time we add a new drawing, we need to modify drawingN
//   - reset perms on drawingN
//   - create new drawingN+1
// - each time we delete a drawing, we need to modify drawingN-1
//   - expand perms on drawing N-1
//   - delete drawingN
// if the oldest drawing is drawing1
// - each time we add a new drawing, we don't need to modify any files
//   - just add drawingN
// - each time we delete a drawing, we need to modify drawing1
//   - update size on drawing1
//   - delete drawingN
// best option seems to be oldest drawing -> drawing1
static int wacomfs_create_listing(struct super_block * superblock)
{
    size_t i;

    IP2NumFilesHeader * num_files_header = NULL;

    unsigned short num_files = 0;
    pr_info("wacomfs: create_listing\n");

    if(IS_ERR_OR_NULL((num_files_header = wacom_smartpad_get_num_files(__wacom_dev)))) return PTR_ERR(num_files_header);

    if((num_files = read_ushort_le(&num_files_header->num_files.raw)) > 0)
    {
        for(i = 0; i < num_files; ++i)
        {
            wacomfs_add_file(superblock);
        }
    }

    return 0;
}

static int wacomfs_unlink(struct inode * inode, struct dentry * entry)
{
    IP2InfoHeader * result = NULL;

    struct super_block * superblock = entry->d_sb;
    pr_info("unlink called\n");

    // only allowed to delete the oldest file, which will be the only one with non-zero size
    if(entry->d_inode->i_size == 0) return -EPERM;

    // execute delete call to tablet
    if(IS_ERR((result = wacom_smartpad_del_file(__wacom_dev)))) return PTR_ERR(result);

    // deallocate last drawing file
    wacomfs_free_last_drawing_file();

    // remove the file from the filesystem
    if(IS_ERR((result = ERR_PTR(wacomfs_delete_file(superblock)))))
    {
        pr_info("wacomfs: unlink: delete_file err\n");
        return PTR_ERR(result);
    }
    // update the new special drawing file
    if(IS_ERR((result = ERR_PTR(wacomfs_update_meta(superblock)))))
    {
        pr_info("wacomfs: unlink: update_meta err\n");
        return PTR_ERR(result);
    }

    // only say we deleted the file when we delete the special file
    return ((struct wacomfs_sb_info*)superblock->s_fs_info)->num_files == 1;
}

static struct inode_operations wacomfs_inode_ops =
{
    .lookup = simple_lookup,
    .unlink = wacomfs_unlink
};

static struct super_operations wacomfs_super_ops =
{
    .statfs = simple_statfs,
    .drop_inode = generic_delete_inode,
};

static int wacomfs_fill_sb(struct super_block * superblock, void * data, int silent)
{
    struct inode * root;

    pr_info("wacomfs: fill_sb\n");

    superblock->s_blocksize = PAGE_CACHE_SIZE;
    superblock->s_blocksize_bits = PAGE_CACHE_SHIFT;
    superblock->s_magic = WACOMFS_MAGIC;
    superblock->s_op = &wacomfs_super_ops;
    superblock->s_fs_info = kzalloc(sizeof(struct wacomfs_sb_info), GFP_KERNEL);

    if(!(root = wacomfs_make_inode(superblock, S_IFDIR | 0755))) return -ENOMEM;

    //root->i_op = &simple_dir_inode_operations;
    root->i_op = &wacomfs_inode_ops;
    root->i_fop = &wacomfs_file_dops;

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
    // deallocate superblock info
    kfree(superblock->s_fs_info);
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
