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
static char* key = 0x0; /* 00:11:22:33 ... */
module_param(key, charp, 0);
static char* backends = 0x0; /* "/path/to/file_1:/path/to/file_2:/path_to_file3:..." */
module_param(backends, charp, 0);

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
static struct splitblk_device {
	unsigned long size;
	spinlock_t lock;
	u8 *data;
	struct gendisk *gd;
} Device;

/*
 * backends-related stuff.
 */

struct splitblk_backend {
  	struct file* f;
	const char* path;
};

#define MAX_BACKENDS 64

static struct splitblk_backend backends_list[MAX_BACKENDS];
static unsigned int backends_count = 0;
static long sp_key[MAX_BACKENDS];
static unsigned int keylen = 0;

/*
 * the splitting algorithm
 */
static struct splitblk_backend *get_backend(unsigned long sector, unsigned long* vol_offset) {

  static unsigned int sum = 0;

  int tmp_offset;
  int i;
  int vid = 0;
  static int *shiftvol = 0x0;

  if (shiftvol == 0x0)
    shiftvol = kmalloc(sizeof(*shiftvol) * backends_count, GFP_KERNEL);

  if (sum == 0)
    for (i = 0; i < keylen; ++i)
      sum += sp_key[i];

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
  return backends_list + vid;
}


/*
 * Handle an I/O request.
 */
static void splitblk_transfer(struct splitblk_device *dev, sector_t sector,
		unsigned long nsect, char *buffer, int write) {
  sector_t s;
  unsigned int i;
  struct splitblk_backend *backend;
  unsigned long offset;

  for (s = sector, i = 0; i < nsect; i++, s++)
  {
    backend = get_backend(s, &offset);
    printk( KERN_DEBUG "sector: %u, got backend %s offset %lu\n", s, backend->path, offset);
  }
}

static void splitblk_request(struct request_queue *q) {
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
		splitblk_transfer(&Device, blk_rq_pos(req), blk_rq_cur_sectors(req),
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
int splitblk_getgeo(struct block_device * block_device, struct hd_geometry * geo) {
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
static struct block_device_operations splitblk_ops = {
		.owner  = THIS_MODULE,
		.getgeo = splitblk_getgeo
};

static int splitblk_backends_init(void) {
  unsigned i, end;
  char *p;

  if (backends == 0x0)
  {
    printk(KERN_WARNING "sbd: missing backends\n");
    return 1;
  }

  for (p = backends, end = 0, i = 0, backends_count = 0, backends_list[0].path = backends; end == 0; ++i) {
    if (backends[i] == ':' || backends[i] == 0x0) {
      if (backends[i] == 0x0)
	end = 1;
      else
        backends[i] = 0x0;
      backends_list[backends_count++].path = p;
      p = backends + i + 1;
    }
  }

  /* need at least two backends */
  if (backends_count <= 1)
    return 1;

  /* open the files */


  return 0;
}

static int splitblk_key_init(void) {
  unsigned i;
  int end;
  char *p;

  if (key == 0x0)
  {
    printk(KERN_WARNING "sbd: missing key\n");
    return 1;
  }

  i = 0;
  p = key;
  keylen = 0;
  end = 0;
  do {
    if (key[i] != ':' && key[i] != '\0') {
      i++;
      continue;
    }
    if (key[i] == 0x0)
      end = 1;
    if (key[i] == ':') {
      key[i] = '\0';
    }
    if (kstrtol(p, 16, &sp_key[keylen])) {
      printk(KERN_WARNING "splitblk: kstrtol failed\n");
      return 1;
    }
    keylen++;
    i++;
    p = &key[i]; /* for the next iteration */
    if (end)
      break;
  } while (1);

  if (keylen >= 1)
    return 0;

  return 1;
}

static int __init splitblk_init(void) {
        unsigned i;
	/*
	 * Set up our internal device.
	 */
	spin_lock_init(&Device.lock);

	if (splitblk_backends_init() || splitblk_key_init())
	  goto out;

	printk(KERN_DEBUG "initialized with %u backends\n", backends_count);

	for (i = 0; i < keylen; ++i)
	  printk(KERN_DEBUG "sp_key[%i] = 0x%x\n", i, sp_key[i]);

	/*
	 * Get a request queue.
	 */
	Queue = blk_init_queue(splitblk_request, &Device.lock);
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
	Device.gd->fops = &splitblk_ops;
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

static void __exit splitblk_exit(void)
{
	del_gendisk(Device.gd);
	put_disk(Device.gd);
	unregister_blkdev(major_num, "splitblk");
	blk_cleanup_queue(Queue);
	vfree(Device.data);
}

module_init(splitblk_init);
module_exit(splitblk_exit);
