/*
 *
 * A pseudo block device splitting blocks across various backends.
 *
 * Original work and copyright:
 * (C) 2003 Eklektix, Inc.
 * (C) 2010 Pat Patterson <pat at superpat dot com>
 * Redistributable under the terms of the GNU GPL.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h> /* printk() */
#include <linux/fs.h>     /* everything... */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>

MODULE_LICENSE("Dual BSD/GPL");
static char *Version = "1.4";

static int major_num = 0;
module_param(major_num, int, 0);
static int logical_block_size = 512;
module_param(logical_block_size, int, 0);
static int nsectors = 8192; /* How big the drive is */
module_param(nsectors, int, 0);
static char* key_arg = ""; /* 00:11:22:33 ... */
module_param(key_arg, charp, 0);
static char* backends_arg = 0x0; /* "/path/to/file_1:/path/to/file_2:/path_to_file3:..." */
module_param(backends_arg, charp, 0);

/*
 * We can tweak our hardware sector size, but the kernel talks to us
 * in terms of small sectors, always.
 */
#define KERNEL_SECTOR_SIZE 512

/*
 * Our request queue.
 */
static struct request_queue *Queue;

/*
 * The internal representation of our device.
 */
static struct sbd_device {
	unsigned long size;
	spinlock_t lock;
	u8 *data;
	struct gendisk *gd;
} Device;

/*
 * backends-related stuff.
 */

struct sp_backend {
  	struct file* f;
	const char* path;
};

#define MAX_BACKENDS 64

static struct sp_backend backends[MAX_BACKENDS];
static unsigned int backends_count = 0;
static unsigned char *key = 0x0;
static unsigned int keylen = 0;

/*
 * the splitting algorithm
 */
static struct sp_backend *get_backend(unsigned long sector, unsigned long* vol_offset) {

  static unsigned int sum = 0;

  int tmp_offset;
  int i;
  int vid = 0;
  static int *shiftvol = 0x0;

  if (shiftvol == 0x0)
    shiftvol = kmalloc(sizeof(*shiftvol) * backends_count, GFP_KERNEL);

  if (sum == 0)
    for (i = 0; i < keylen; ++i)
      sum += key[i];

  tmp_offset = sector / (sum * backends_count) * sum;
  sector = sector % (sum * backends_count); 

  for (i = 0; i < backends_count; ++i) 
    shiftvol[i] = 0;

  i = 0;
  while (sector >= key[i]) {
    sector -= key[i];
    shiftvol[vid] += key[i];
    vid = (vid + 1) % backends_count;
    i = (i + 1) % (keylen);
  }
  tmp_offset += sector + shiftvol[vid];

  *vol_offset = tmp_offset;
  return backends + vid;
}


/*
 * Handle an I/O request.
 */
static void sbd_transfer(struct sbd_device *dev, sector_t sector,
		unsigned long nsect, char *buffer, int write) {

}

static void sbd_request(struct request_queue *q) {
	struct request *req;

	req = blk_fetch_request(q);
	while (req != NULL) {
		// blk_fs_request() was removed in 2.6.36 - many thanks to
		// Christian Paro for the heads up and fix...
		//if (!blk_fs_request(req)) {
		if (req == NULL || (req->cmd_type != REQ_TYPE_FS)) {
			printk (KERN_NOTICE "Skip non-CMD request\n");
			__blk_end_request_all(req, -EIO);
			continue;
		}
		sbd_transfer(&Device, blk_rq_pos(req), blk_rq_cur_sectors(req),
				bio_data(req->bio), rq_data_dir(req));
		if ( ! __blk_end_request_cur(req, 0) ) {
			req = blk_fetch_request(q);
		}
	}
}

/*
 * The HDIO_GETGEO ioctl is handled in blkdev_ioctl(), which
 * calls this. We need to implement getgeo, since we can't
 * use tools such as fdisk to partition the drive otherwise.
 */
int sbd_getgeo(struct block_device * block_device, struct hd_geometry * geo) {
	long size;

	/* We have no real geometry, of course, so make something up. */
	size = Device.size * (logical_block_size / KERNEL_SECTOR_SIZE);
	geo->cylinders = (size & ~0x3f) >> 6;
	geo->heads = 4;
	geo->sectors = 16;
	geo->start = 0;
	return 0;
}

/*
 * The device operations structure.
 */
static struct block_device_operations sbd_ops = {
		.owner  = THIS_MODULE,
		.getgeo = sbd_getgeo
};

static int backends_init(void) {
  unsigned i;
  unsigned backend_index = 0;

  if (backends_arg == 0x0)
    return 1;

  for (i = 0, backends[0].path = backends_arg; backends_arg[i]; ++i) {
    if (backends_arg[i] == ':') {
      backends_arg[i++] = 0x0;
      backends[++backend_index].path = &backends_arg[i];
    }
  }

  /* need at least two backends */
  if (backend_index > 1)
    return 1;

  return 0;
}

static int __init sbd_init(void) {
	/*
	 * Set up our internal device.
	 */
	spin_lock_init(&Device.lock);

	if (backends_init())
	  goto out;

	/*
	 * Get a request queue.
	 */
	Queue = blk_init_queue(sbd_request, &Device.lock);
	if (Queue == NULL)
		goto out;
	blk_queue_logical_block_size(Queue, logical_block_size);
	/*
	 * Get registered.
	 */
	major_num = register_blkdev(major_num, "splitblk");
	if (major_num < 0) {
		printk(KERN_WARNING "sbd: unable to get major number\n");
		goto out;
	}
	/*
	 * And the gendisk structure.
	 */
	Device.gd = alloc_disk(16);
	if (!Device.gd)
		goto out_unregister;
	Device.gd->major = major_num;
	Device.gd->first_minor = 0;
	Device.gd->fops = &sbd_ops;
	Device.gd->private_data = &Device;
	strcpy(Device.gd->disk_name, "splitblk0");
	set_capacity(Device.gd, nsectors);
	Device.gd->queue = Queue;
	add_disk(Device.gd);

	return 0;

out_unregister:
	unregister_blkdev(major_num, "splitblk");
out:
	vfree(Device.data);
	return -ENOMEM;
}

static void __exit sbd_exit(void)
{
	del_gendisk(Device.gd);
	put_disk(Device.gd);
	unregister_blkdev(major_num, "splitblk");
	blk_cleanup_queue(Queue);
	vfree(Device.data);
}

module_init(sbd_init);
module_exit(sbd_exit);
