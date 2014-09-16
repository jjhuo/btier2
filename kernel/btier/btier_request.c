/*
 * Btier bio request handling related funtions, block layer will call btier
 * make_request to handle block read and write requests.
 *
 * Copyright (C) 2014 Mark Ruijter, <mruijter@gmail.com>
 * 
 */

#include "btier.h"
/*
static int get_chunksize(struct block_device *bdev, struct bio *bio)
{
        struct request_queue *q = bdev_get_queue(bdev);
        unsigned int chunksize;
        unsigned int max_hwsectors;
        unsigned int max_sectors;
	unsigned ret = 0, seg = 0;	
	struct bio_vec bv;
	struct bvec_iter iter;

        max_hwsectors = queue_max_hw_sectors(q);
        max_sectors = queue_max_sectors(q);
        chunksize = min(max_hwsectors, max_sectors) << 9;

	bio_for_each_segment(bv, bio, iter) {
		struct bvec_merge_data bvm = {
			.bi_bdev        = bdev,
			.bi_sector      = bio->bi_iter.bi_sector,
			.bi_size        = ret,
			.bi_rw          = bio->bi_rw,
		};

		if (seg == min_t(unsigned, BIO_MAX_PAGES,
				 queue_max_segments(q)))
			break;

		if (q->merge_bvec_fn &&
		    q->merge_bvec_fn(q, &bvm, &bv) < (int) bv.bv_len)
			break;

		seg++;
		ret += bv.bv_len;
	}

	chunksize =  min(ret, chunksize);
	WARN_ON(!chunksize);
	
        if ( chunksize < PAGE_SIZE )
            chunksize = PAGE_SIZE;
        if ( chunksize > BLKSIZE )
            chunksize = BLKSIZE;

        return chunksize;
}*/

int get_chunksize(struct block_device *bdev)
{
        struct request_queue *q = bdev_get_queue(bdev);
        unsigned int chunksize;
        unsigned int max_hwsectors_kb;

        max_hwsectors_kb = queue_max_hw_sectors(q);
        chunksize = max_hwsectors_kb << 9;
        if (chunksize < PAGE_SIZE)
            chunksize = PAGE_SIZE;
        if (chunksize > BLKSIZE)
            chunksize = BLKSIZE;
        return chunksize;
}

static void determine_iotype(struct tier_device *dev, u64 blocknr)
{
	int ioswitch = 0;
	if (blocknr >= dev->lastblocknr && blocknr <= dev->lastblocknr + 1) {
		ioswitch = 1;
	}
	if (ioswitch && dev->insequence < 10)
		dev->insequence++;
	else {
		if (dev->insequence > 0)
			dev->insequence--;
	}
	if (dev->insequence > 5) {
		dev->iotype = SEQUENTIAL;
	} else {
		dev->iotype = RANDOM;
	}
	dev->lastblocknr = blocknr;
}

/* Check for corruption */
static int binfo_sanity(struct tier_device *dev, struct blockinfo *binfo)
{
	struct backing_device *backdev = dev->backdev[binfo->device - 1];
	if (binfo->device > dev->attached_devices) {
		pr_info
		    ("Metadata corruption detected : device %u, dev->attached_devices %u\n",
		     binfo->device, dev->attached_devices);
		tiererror(dev,
			  "get_blockinfo : binfo->device > dev->attached_devices");
		return 0;
	}

	if (binfo->offset > backdev->devicesize) {
		pr_info
		    ("Metadata corruption detected : device %u, offset %llu, devsize %llu\n",
		     binfo->device, binfo->offset, backdev->devicesize);
		tiererror(dev, "get_blockinfo : offset exceeds device size");
		return 0;
	}
	return 1;
}

/*  Read the metadata of the blocknr specified
 *  When a blocknr is not yet allocated binfo->device is 0
 *  otherwhise > 0 
 *  Metadata statistics are updated when called with 
 *  TIERREAD or TIERWRITE (updatemeta != 0 )
 */
struct blockinfo *get_blockinfo(struct tier_device *dev, u64 blocknr,
				int updatemeta)
{
	/* The blocklist starts at the end of the bitlist on device1 */
	struct blockinfo *binfo;
	struct backing_device *backdev = dev->backdev[0];

	if (dev->inerror)
		return NULL;
	/* 
	 * random reads are multithreaded, so lock the 
	 * blocklist cache up-on modification
	 */
	spin_lock_irq(&dev->statlock);
	binfo = backdev->blocklist[blocknr];
	if (0 != binfo->device) {
		if (!binfo_sanity(dev, binfo)) {
			binfo = NULL;
			goto err_ret;
		}
		backdev = dev->backdev[binfo->device - 1];
		
		/* update accesstime and hitcount */
		if (updatemeta > 0) {
			if (updatemeta == TIERREAD) {
				if (binfo->readcount < MAX_STAT_COUNT) {
					binfo->readcount++;
					backdev->devmagic->total_reads++;
				}
			} else {
				if (binfo->writecount < MAX_STAT_COUNT) {
					binfo->writecount++;
					backdev->devmagic->total_writes++;
				}
			}
			binfo->lastused = get_seconds();
			(void)write_blocklist(dev, blocknr, binfo, WC);
		}
	}
err_ret:
	spin_unlock_irq(&dev->statlock);
	return binfo;
}

static int allocate_block(struct tier_device *dev, u64 blocknr,
			  struct blockinfo *binfo)
{
	int device = 0;
	int count = 0;

/* Sequential writes will go to SAS or SATA */
	if (dev->iotype == SEQUENTIAL && dev->attached_devices > 1)
		device =
		    dev->backdev[0]->devmagic->dtapolicy.sequential_landing;
	while (1) {
		if (0 != allocate_dev(dev, blocknr, binfo, device))
			return -EIO;
		if (0 != binfo->device) {
			if (0 != write_blocklist(dev, blocknr, binfo, WA))
				return -EIO;
			break;
		}
		device++;
		count++;
		if (count >= dev->attached_devices) {
			pr_err
			    ("no free space found, this should never happen!!\n");
			return -ENOSPC;
		}
		if (device >= dev->attached_devices)
			device = 0;
	}
	return 0;
}

static inline void bio_write_done(struct bio *bio, int err)
{
	struct bio_task *bio_task = bio->bi_private;
	struct tier_device *dev = bio_task->dev;
	if (err)
		tiererror(dev, "write error\n");
	if (atomic_dec_and_test(&bio_task->pending)) {
		if (dev->inerror) {
			bio_endio(bio_task->parent_bio, -EIO);
		} else
			bio_endio(bio_task->parent_bio, 0);
	}
	atomic_dec(&dev->aio_pending);
	wake_up(&dev->aio_event);
	bio_put(bio);
}

static inline void bio_read_done(struct bio *bio, int err)
{
	struct bio_task *bio_task = bio->bi_private;
	struct tier_device *dev = bio_task->dev;
	if (err)
		tiererror(dev, "read error\n");
	if (atomic_dec_and_test(&bio_task->pending)) {
		if (dev->inerror) {
			bio_endio(bio_task->parent_bio, -EIO);
		} else
			bio_endio(bio_task->parent_bio, 0);
	}
	atomic_dec(&dev->aio_pending);
	wake_up(&dev->aio_event);
	bio_put(bio);
}

static struct bio *prepare_bio_req(struct tier_device *dev, unsigned int device,
				   struct bio_vec *bvec, u64 offset,
				   struct bio_task *bio_task)
{
	struct block_device *bdev = dev->backdev[device]->bdev;
        struct bio *bio;
  
        if (bio_task->in_one) {
		bio = bio_clone(bio_task->parent_bio, GFP_NOIO);
		if (!bio) {
			tiererror(dev, "bio_clone failed\n");
			return NULL;
		}
        } else {
		bio = bio_alloc(GFP_NOIO, 1);
		if (!bio) {
			tiererror(dev, "bio_clone failed\n");
			return NULL;
		}
		bio->bi_bdev = bdev;
		bio->bi_io_vec[0].bv_page = bvec->bv_page;
		bio->bi_io_vec[0].bv_len = bvec->bv_len;
		bio->bi_io_vec[0].bv_offset = bvec->bv_offset;
		bio->bi_vcnt = 1;
		bio->bi_iter.bi_size = bvec->bv_len;
        }
	bio->bi_iter.bi_sector = offset >> 9;
	bio->bi_iter.bi_idx = 0;
	bio->bi_private = bio_task;
	bio->bi_bdev = bdev;
	return bio;
}

static int tier_write_page(unsigned int device,
                           struct bio_vec *bvec, u64 offset,
                           struct bio_task *bio_task)
{
        struct bio *bio;
        struct tier_device *dev = bio_task->dev;
        set_debug_info(dev, BIOWRITE);
        bio = prepare_bio_req(dev, device, bvec, offset, bio_task);
        if (!bio) {
                tiererror(dev, "bio_alloc failed from tier_write_page\n");
		return -EIO;
	}
        bio->bi_end_io = bio_write_done;
        bio->bi_rw = WRITE;
        atomic_inc(&dev->aio_pending);
        submit_bio(WRITE, bio);
        clear_debug_info(dev, BIOWRITE);
        return 0;
}

static int tier_read_page(unsigned int device,
			  struct bio_vec *bvec, u64 offset,
			  struct bio_task *bio_task)
{
	struct bio *bio;
        struct tier_device *dev = bio_task->dev;
	set_debug_info(dev, BIOREAD);
	bio = prepare_bio_req(dev, device, bvec, offset, bio_task);
	if (!bio) {
		tiererror(dev, "bio_alloc failed from tier_write_page\n");
		return -EIO;
	}
	bio->bi_end_io = bio_read_done;
	bio->bi_rw = READ;
	atomic_inc(&dev->aio_pending);
	submit_bio(READ, bio);
	clear_debug_info(dev, BIOREAD);
	return 0;
}

static int read_tiered(void *data, unsigned int len,
                       u64 offset, struct bio_vec *bvec,
		       struct bio_task *bio_task)
{
	struct blockinfo *binfo = NULL;
	u64 blocknr;
	unsigned int block_offset;
	int res = 0;
	int size = 0;
	unsigned int done = 0;
	u64 curoff;
	unsigned int device;
        unsigned int chunksize=PAGE_SIZE;
	int keep = 0;
        struct tier_device *dev = bio_task->dev;
	struct bio *parent_bio  = bio_task->parent_bio;

	if (dev->iotype == RANDOM)
		dev->stats.rand_reads++;
	else
		dev->stats.seq_reads++;
	if (len == 0)
		return -1;
	while (done < len) {
		curoff = offset + done;
		blocknr = curoff >> BLKBITS;
		block_offset = curoff - (blocknr << BLKBITS);

		binfo = get_blockinfo(dev, blocknr, TIERREAD);
		if (dev->inerror) {
			res = -EIO;
			break;
		}
		if (len - done + block_offset > BLKSIZE) {
			size = BLKSIZE - block_offset;
		} else
			size = len - done;
		if (0 == binfo->device) {
			memset(data + done, 0, size);
			res = 0;
			if (atomic_dec_and_test(&bio_task->pending)) {
				if (dev->inerror) {
					bio_endio(bio_task->parent_bio, -EIO);
				} else
					bio_endio(bio_task->parent_bio, 0);
			}
		} else {
			device = binfo->device - 1;
			if (dev->backdev[device]->bdev) {
                                if(done == 0 && offset == (parent_bio->bi_iter.bi_sector << 9)) {
                                     chunksize = get_chunksize(dev->backdev[device]->bdev);
                                     if ( parent_bio->bi_iter.bi_size <= chunksize &&
                                          block_offset + parent_bio->bi_iter.bi_size <= BLKSIZE )
                                         bio_task->in_one = 1;
                                }
				res =
				    tier_read_page(device, bvec,
						   binfo->offset + block_offset,
						   bio_task);
			} 
		}
		done += size;
		if (res != 0 || bio_task->in_one)
			break;
	}
	if (!keep)
		kunmap(bvec->bv_page);
	return res;
}

static int write_tiered(void *data, unsigned int len,
			u64 offset, struct bio_vec *bvec,
			struct bio_task *bio_task)
{
	struct blockinfo *binfo;
	u64 blocknr;
	unsigned int block_offset;
	int res = 0;
	unsigned int size = 0;
	unsigned int done = 0;
	u64 curoff;
	unsigned int device;
        unsigned int chunksize=PAGE_SIZE;
        struct tier_device *dev = bio_task->dev;
	struct bio *parent_bio  = bio_task->parent_bio;

	if (dev->iotype == RANDOM)
		dev->stats.rand_writes++;
	else
		dev->stats.seq_writes++;
	while (done < len) {
		curoff = offset + done;
		blocknr = curoff >> BLKBITS;
		block_offset = curoff - (blocknr << BLKBITS);
		set_debug_info(dev, PREBINFO);
		binfo = get_blockinfo(dev, blocknr, TIERWRITE);
		clear_debug_info(dev, PREBINFO);
		if (dev->inerror) {
			res = -EIO;
			break;
		}
		if (len - done + block_offset > BLKSIZE) {
			size = BLKSIZE - block_offset;
		} else
			size = len - done;
		if (0 == binfo->device) {
			set_debug_info(dev, PREALLOCBLOCK);
			res = allocate_block(dev, blocknr, binfo);
			clear_debug_info(dev, PREALLOCBLOCK);
			if (res != 0) {
				pr_crit("Failed to allocate_block\n");
				return res;
			}
		}
		device = binfo->device - 1;
		if (dev->backdev[device]->bdev) {
                        if(done == 0 && offset == (parent_bio->bi_iter.bi_sector << 9)) {
                             chunksize = get_chunksize(dev->backdev[device]->bdev);
                             if (parent_bio->bi_iter.bi_size <= chunksize &&
                                 block_offset + parent_bio->bi_iter.bi_size <= BLKSIZE )
                                 bio_task->in_one = 1;
                        }
			res =
			    tier_write_page(device, bvec,
					    binfo->offset + block_offset,
					    bio_task);
		}
		done += size;
		if (res != 0 || bio_task->in_one)
			break;
	}
	return res;
}

static void tier_add_bio(struct tier_device *dev, struct bio *bio)
{
	bio_list_add(&dev->tier_bio_list, bio);
}

/*
 * Grab first pending buffer
 */
static struct bio *tier_get_bio(struct tier_device *dev)
{
	return bio_list_pop(&dev->tier_bio_list);
}

static int tier_do_bio(struct bio_task *bio_task)
{
	loff_t offset;
	int ret = 0;
	u64 blocknr = 0;
	char *buffer;
        struct tier_device *dev = bio_task->dev;
	struct bio *bio = bio_task->parent_bio;
	struct bio_vec bvec;
	struct bvec_iter iter;
	const u64 do_sync = (bio->bi_rw & REQ_SYNC);

	atomic_set(&dev->wqlock, NORMAL_IO);
	mutex_lock(&dev->qlock);

	offset = ((loff_t) bio->bi_iter.bi_sector << 9);
	blocknr = offset >> BLKBITS;

	if (bio_rw(bio) == WRITE) {
		if (bio->bi_rw & REQ_FLUSH) {
			if (dev->barrier) {
				ret = tier_sync(dev);
				if (unlikely(ret && ret != -EINVAL)) {
					ret = -EIO;
					goto out;
				}
			}
		}
		if (bio->bi_rw & REQ_DISCARD) {
			set_debug_info(dev, DISCARD);
			pr_debug("Got a discard request offset %llu len %u\n",
				 offset, bio->bi_iter.bi_size);
			tier_discard(dev, offset, bio->bi_iter.bi_size);
			set_debug_info(dev, DISCARD);
		}
	}

	bio_for_each_segment(bvec, bio, iter) {
		determine_iotype(dev, blocknr);
		atomic_inc(&bio_task->pending);
		if (bio_rw(bio) == WRITE) {
			buffer = kmap(bvec.bv_page);
			ret =
			    write_tiered(buffer + bvec.bv_offset,
					 bvec.bv_len, offset, &bvec, bio_task);
			kunmap(bvec.bv_page);
		} else {
			buffer = kmap(bvec.bv_page);
			ret = read_tiered(buffer + bvec.bv_offset,
					  bvec.bv_len, offset, &bvec, bio_task);
		}
		if (ret < 0)
			break;
		offset += bvec.bv_len;
		blocknr = offset >> BLKBITS;
                if (bio_task->in_one)
                    break;
	}
	
	if (bio_rw(bio) == WRITE) {
		if (bio->bi_rw & REQ_FUA) {
			if (dev->barrier) {
				ret = tier_sync(dev);
				if (unlikely(ret && ret != -EINVAL))
					ret = -EIO;
			}
		}
		if (do_sync && dev->ptsync) {
			ret = tier_sync(dev);
			if (unlikely(ret && ret != -EINVAL))
				ret = -EIO;
		}
	}

	if (atomic_dec_and_test(&bio_task->pending)) {
		if (dev->inerror) {
			bio_endio(bio_task->parent_bio, -EIO);
		} else
			bio_endio(bio_task->parent_bio, 0);
	}
out:
	atomic_set(&dev->wqlock, 0);
	mutex_unlock(&dev->qlock);
	return ret;
}

static inline void tier_handle_bio(struct bio_task *bio_task)
{
	int ret;
        struct tier_device *dev = bio_task->dev;
	ret = tier_do_bio(bio_task);
	if (ret != 0)
		dev->inerror = 1;
}

static inline void tier_wait_bio(struct bio_task *bio_task)
{
	struct tier_device *dev = bio_task->dev;
	if (0 != atomic_read(&dev->aio_pending)) {
		set_debug_info(dev, WAITAIOPENDING);
		wait_event(dev->aio_event, 0 == atomic_read(&dev->aio_pending));
		clear_debug_info(dev, WAITAIOPENDING);
	}
}

int tier_thread(void *data)
{
	struct tier_device *dev = data;
	struct bio_task **bio_task;
	int backlog;
	int i;

	set_user_nice(current, -20);
	bio_task =
	    kzalloc(BTIER_MAX_INFLIGHT * sizeof(struct bio_task *), GFP_KERNEL);
	if (!bio_task) {
		tiererror(dev, "tier_thread : alloc failed");
		return -ENOMEM;
	}
	for (i = 0; i < BTIER_MAX_INFLIGHT; i++) {
		bio_task[i] = kzalloc(sizeof(struct bio_task), GFP_KERNEL);
		if (!bio_task[i]) {
			tiererror(dev, "tier_thread : alloc failed");
			for (i--; i >= 0; i--) {
				kfree(bio_task[i]);
			}	
			return -ENOMEM;
		}
		bio_task[i]->dev = dev;
		atomic_set(&bio_task[i]->pending, 0);
	}
	while (!kthread_should_stop() || !bio_list_empty(&dev->tier_bio_list)) {

		wait_event_interruptible(dev->tier_event,
					 !bio_list_empty(&dev->tier_bio_list) ||
					 kthread_should_stop());
		if (bio_list_empty(&dev->tier_bio_list))
			continue;
		backlog = 0;
		do {
			atomic_set(&bio_task[backlog]->pending, 1);
			spin_lock_irq(&dev->lock);
			bio_task[backlog]->parent_bio = tier_get_bio(dev);
			spin_unlock_irq(&dev->lock);
			BUG_ON(!bio_task[backlog]->parent_bio);
			tier_handle_bio(bio_task[backlog]);
			backlog++;
			/* 
			 * When reading sequential we stay on a single thread
			 * and a single filedescriptor
			 */
		} while (!bio_list_empty(&dev->tier_bio_list)
			 && backlog < BTIER_MAX_INFLIGHT);
		if (dev->writethrough)
			tier_sync(dev);
		for (i = 0; i < backlog; i++) {
			tier_wait_bio(bio_task[i]);
                        bio_task[i]->in_one = 0;
		}
	}
	for (i = 0; i < BTIER_MAX_INFLIGHT; i++) {
		kfree(bio_task[i]);
	}
	kfree(bio_task);
	pr_info("tier_thread worker halted\n");
	return 0;
}

/*
 * 1. if bio size is 0, flag is flush, flush metadata
*/
void tier_make_request(struct request_queue *q, struct bio *old_bio)
{
	int cpu;
	struct tier_device *dev = q->queuedata;
	int rw = bio_rw(old_bio);

	if (rw == READA)
		rw = READ;

	BUG_ON(!dev || (rw != READ && rw != WRITE));
	spin_lock_irq(&dev->lock);
	if (!dev->active)
		goto out;
	cpu = part_stat_lock();
	part_stat_inc(cpu, &dev->gd->part0, ios[rw]);
	part_stat_add(cpu, &dev->gd->part0, sectors[rw], bio_sectors(old_bio));
	part_stat_unlock();
	tier_add_bio(dev, old_bio);
	wake_up(&dev->tier_event);
	spin_unlock_irq(&dev->lock);
	goto end_return;

out:
	spin_unlock_irq(&dev->lock);
	bio_io_error(old_bio);

end_return:
	return;
}
