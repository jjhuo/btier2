/*
 * Btier bio request handling related funtions, block layer will call btier
 * make_request to handle block read and write requests.
 *
 * Copyright (C) 2014 Mark Ruijter, <mruijter@gmail.com>
 * 
 * Btier bio make_request handling rewrite, fine grained locking in blocklist,
 * and etc. Jianjian Huo <samuel.huo@gmail.com> - September 2014.
 * Get_chunksize function is reused from bcache.
 * 
 */

#include "btier.h"

struct kmem_cache *bio_task_cache;

static unsigned int get_chunksize(struct block_device *bdev,
				  struct bio *bio)
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
	/* chunksize should be aligned with sectors */
	WARN_ON(chunksize&(1 << 9 - 1));

	ret = max_t(int, chunksize, bio_iovec(bio).bv_len);

        if (chunksize > BLKSIZE)
            chunksize = BLKSIZE;

        return chunksize;
}

static void determine_iotype(struct bio_task *bt, u64 blocknr)
{
	int ioswitch = 0;
	struct tier_device *dev = bt->dev;

	spin_lock(&dev->io_stat_lock);

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
		bt->iotype = SEQUENTIAL;
	} else {
		bt->iotype = RANDOM;
	}

	dev->lastblocknr = blocknr;

	if (bt->iotype == RANDOM)
		dev->stats.rand_reads++;
	else
		dev->stats.seq_reads++;

	spin_unlock(&dev->io_stat_lock);
}

/* from bio->bi_iter.bi_sector, memset size of it to 0;
   size is guaranteed to be <= bi_size */
static void bio_fill_zero(struct bio *bio, unsigned int size)
{
	unsigned long flags;
	struct bio_vec bv;
	struct bvec_iter iter;
	unsigned int done = 0;

	bio_for_each_segment(bv, bio, iter) {
		char *data = bvec_kmap_irq(&bv, &flags);
		memset(data, 0, bv.bv_len);
		flush_dcache_page(bv.bv_page);
		bvec_kunmap_irq(data, &flags);

		done += bv.bv_len;
		if (done >= size)
			break;
	}
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

/*
 * Read the metadata of the blocknr specified.
 * When a blocknr is not yet allocated binfo->device is 0; otherwhise > 0.
 * Metadata statistics are updated when called with 
 * TIERREAD or TIERWRITE (updatemeta != 0 )
 *
 * After function is called, spinlock in blockinfo will be locked.
 */
struct blockinfo *get_blockinfo(struct tier_device *dev, u64 blocknr,
				int updatemeta)
{
	/* The blocklist starts at the end of the bitlist on device1 */
	struct blockinfo *binfo;
	struct backing_device *backdev = dev->backdev[0];

	if (dev->inerror)
		return NULL;

	binfo = backdev->blocklist[blocknr];

	spin_lock(&binfo->lock);

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
					spin_lock(&backdev->magic_lock);
					backdev->devmagic->total_reads++;
					spin_unlock(&backdev->magic_lock);
				}
			} else {
				if (binfo->writecount < MAX_STAT_COUNT) {
					binfo->writecount++;
					spin_lock(&backdev->magic_lock);
					backdev->devmagic->total_writes++;
					spin_unlock(&backdev->magic_lock);
				}
			}

			binfo->lastused = get_seconds();
		}
	}
	
err_ret:
	return binfo;
}

static int allocate_block(struct tier_device *dev, u64 blocknr,
			  struct blockinfo *binfo)
{
	int device = 0;
	int count = 0;

/* Sequential writes will go to SAS or SATA */
	if (dev->iotype == SEQUENTIAL && dev->attached_devices > 1) {
		spin_lock(&backdev->magic_lock);
		device =
		    dev->backdev[0]->devmagic->dtapolicy.sequential_landing;
		spin_unlock(&backdev->magic_lock);
	}

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

/* Reset blockinfo for this block to unused and clear the
   bitlist for this block
*/
void tier_discard(struct tier_device *dev, u64 offset, unsigned int size)
{
	struct blockinfo *binfo;
	u64 blocknr;
	u64 lastblocknr;
	u64 curoff;
	u64 start;

	pr_debug("Got a discard request offset %llu len %u\n",
		 offset, size);

	if (!dev->discard)
		return;
	curoff = offset + size;
	lastblocknr = curoff >> BLKBITS;
	start = offset >> BLKBITS;
	/* Make sure we don't discard a block while a part of it is still inuse */
	if ((start << BLKBITS) < offset)
		start++;
	if ((start << BLKBITS) > (offset + size))
		return;

	for (blocknr = start; blocknr < lastblocknr; blocknr++) {
		binfo = get_blockinfo(dev, blocknr, 0);
		if (dev->inerror) {
			break;
		}
		if (binfo->device != 0) {
			pr_debug
			    ("really discard blocknr %llu at offset %llu size %u\n",
			     blocknr, offset, size);
			clear_dev_list(dev, binfo);
			reset_counters_on_migration(dev, binfo);
			discard_on_real_device(dev, binfo);
			memset(binfo, 0, sizeof(struct blockinfo));
			write_blocklist(dev, blocknr, binfo, WA);
		}

		cond_resched();
	}
}

/* 
 * Btier meta data operations, such as FLUSH/FUA, discard, and read/write
 * blocklist and bit list on backing devices.
 * Pending make_request will be waiting for those to be finished.
 * Cannot call them under generic_make_request, use a work queue.
 */
static void tier_meta_work(struct work_struct *work)
{
	struct bio_meta *bm = container_of(work, struct bio_meta, work);
	struct tier_device *dev = bm->dev;
	struct bio *bio = &bm->bio;
	struct bio *parent_bio = &bm->parent_bio;
	int i, ret = 0;

	/*
	 * if bm->flush is true, flush possible dirty meta data if has.
	 * Currently, we don't have, other than r/w counts in block info. 
	 */
	if (bm->flush) {
		/* send this zero size bio to every backing device*/
		set_debug_info(dev, PRESYNC);
		for (i = 0; i < dev->attached_devices; i++) {
			bio->bi_bdev = dev->backdev[i]->bdev;
			ret |= submit_bio_wait(bio->bi_rw, bio);
		}
		clear_debug_info(dev, PRESYNC);
	}

	if (bm->discard) {
		set_debug_info(dev, DISCARD);
		tier_discard(dev, parent_bio->bi_iter.bi_sector << 9, 
			     parent_bio->bi_iter.bi_size);
		clear_debug_info(dev, DISCARD);
	}

	bm->ret = ret;
	complete(&bm->event);
}

static void tier_submit_and_wait_meta(struct bio_meta *bm)
{
	int ret = 0;
	struct tier_device *dev = bm->dev;

	init_completion(&bm->event);
	INIT_WORK(&bm->work, tier_dev_meta);
	ret = queue_work(btier_wq, &bm->work);
	BUG_ON(!ret);

	/* wait until all those bio meta works have been finished*/
	wait_for_completion(&bm->event);

	if (bm->ret) {
		bio_endio(bm->parent_bio, -EIO);
	} else
		bio_endio(bm->parent_bio, 0);

	atomic_dec(&dev->aio_pending);
	wake_up(&dev->aio_event);
	mempool_free(bm, dev->bio_meta);
}

static inline void tier_dev_nodata(struct tier_device *dev,
				   struct bio *parent_bio)
{
	bio_meta *bm;

	bm = mempool_alloc(dev->bio_meta, GFP_NOIO);
	memset(bm, 0, sizeof(*bm));

	bm->dev = dev;
	bm->flush = (parent_bio->bi_rw & (REQ_FLUSH|REQ_FUA)) != 0;
	bm->parent_bio = parent_bio;

	bio_init(&bm->bio);
	__bio_clone_fast(&bm->bio, parent_bio);
	
	tier_submit_and_wait_meta(bm);
}

static inline void tier_dev_discard(struct tier_device *dev,
				    struct bio *parent_bio)
{
	bio_meta *bm;

	bm = mempool_alloc(dev->bio_meta, GFP_NOIO);
	memset(bm, 0, sizeof(*bm));

	bm->dev = dev;
	bm->discard = 1;
	bm->parent_bio = parent_bio;

	tier_submit_and_wait_meta(bm);
}

static void request_endio(struct bio *bio, int err)
{
	struct bio_task *bio_task = bio->bi_private;
	struct tier_device *dev = bio_task->dev;

	if (err)
		tiererror(dev, "btier request error\n");

	if (dev->inerror) {
		bio_endio(bio_task->parent_bio, -EIO);
	} else
		bio_endio(bio_task->parent_bio, 0);

	atomic_dec(&dev->aio_pending);
	wake_up(&dev->aio_event);
	mempool_free(bio_task, dev->bio_task);
}

static void tier_submit_bio(struct tier_device *dev,
				unsigned int device,
				struct bio *bio,
				sector_t start_sector)
{
	struct block_device *bdev = dev->backdev[device]->bdev;

	set_debug_info(dev, BIO);

	bio->bi_iter.bi_sector	= start_sector;
	bio->bi_bdev		= bdev;

	generic_make_request(bio);
	clear_debug_info(dev, BIO);
}

/*static struct bio *prepare_bio_req(struct tier_device *dev, unsigned int device,
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

				if(done)
					atomic_inc(&bio_task->pending);

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
}*/

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

			if(done)
				atomic_inc(&bio_task->pending);

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
/*
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
			//samuel: should then skip bio_for_each_segment.
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
}*/

static void tiered_dev_write(struct bio_task *bt, struct tier_device *dev)
{

}

static void tiered_dev_read(struct bio_task *bt, struct tier_device *dev)
{
	struct bio *bio = bt->bio;
	u64 end_blk, cur_blk, offset;
	struct block_info *binfo;
	unsigned int offset_in_blk, size_in_blk;

	end_blk = (bio_end_sector(bio) << 9) >> BLKBITS;

	while (cur_blk <= end_blk) {
		offset = bio->bi_iter.bi_sector << 9;
		cur_blk = offset >> BLKBITS;
		offset_in_blk = offset - (cur_blk << BLKBITS);
		size_in_blk = (cur_blk == end_blk) ? bio->bi_iter.bi_size :
						     (BLKSIZE - offset_in_blk);	

		determine_iotype(bt, cur_blk);

		binfo = get_blockinfo(dev, cur_blk, TIERREAD);

		/* unallocated block, return data zero */
		if (unlikely(0 == binfo->device)) {
			bio_fill_zero(bio, size_in_blk);

			bio_advance(bio, size_in_blk);

			/* total splits is 0 and it's now last blk of bio.*/
			if (1 == atomic_read(bio->bi_remaining) && 
			    cur_blk == end_blk) {
				spin_unlock(&binfo->lock);
				if (dev->inerror)
					bio_endio(bt->parent_bio, -EIO);
				else
					bio_endio(bt->parent_bio, 0);
				
				goto bio_done;
			}

			/* total splits > 0 and it's now last blk of bio */
			if (atomic_read(&bio->bi_remaining) > 1 && 
			    cur_blk == end_blk)
				atomic_dec(&bio->bi_remaining);

			spin_unlock(&binfo->lock);
			continue;
		}

		/* allocated block, split bio within it */
		unsigned int done = 0;
		unsigned int cur_chunk = 0;
		sector_t start = 0;
		unsigned int device = binfo->device - 1;

		do {
			cur_chunk = get_chunksize(dev, bio);
			if (cur_chunk > (size_in_blk - done))
				cur_chunk = size_in_blk - done;
	
			/* if no splits, and it's now last blk of bio */
			if (1 == atomic_read(bio->bi_remaining) && 
			    cur_blk == end_blk && 
			    cur_chunk == size_in_blk) {
				start = (binfo->offset + offset_in_blk) >> 9;
				spin_unlock(&binfo->lock);
				tier_submit_bio(dev, device, bio, start);
				goto bio_submitted_lastbio;
			}

			struct bio *split;
			split = bio_next_split(bio, cur_chunk >> 9, 
					       GFP_NOIO, fs_bio_set);
			if (split == bio) {
				BUG_ON(cur_blk != end_blk);
				start = (binfo->offset + offset_in_blk + done)
					>> 9;
				spin_unlock(&binfo->lock);
				tier_submit_bio(dev, device, bio, start);
				goto bio_submitted_lastbio;
			} else {
				bio_chain(split, bio);
				start = (binfo->offset + offset_in_blk + done)
					>> 9;
				spin_unlock(&binfo->lock);
				tier_submit_bio(dev, device, split, start);
			}

			done += cur_chunk;
		} while (done != size_in_blk);
	}

	return;

bio_done:
	bio_put(bio);
	mempool_free(bt, dev->bio_task);
	atomic_dec(&dev->aio_pending);
	wake_up(&dev->aio_event);
bio_submitted_lastbio:
	return;
}

static inline struct bio_task *task_alloc(struct bio *parent_bio,
					  struct tier_device *dev)
{
	struct bio_task *bt;
	struct bio *bio;

	bt = mempool_alloc(dev->bio_task, GFP_NOIO);
	memset(bt, 0, sizeof(*bt));

	bt->parent_bio = parent_bio;
	bt->dev = dev;
	bt->iotype = RANDOM;

	bio = &bt->bio;
	bio_init(bio);
	__bio_clone_fast(bio, parent_bio);
	bio->bi_end_io  = request_endio;
	bio->bi_private = bt;

	/* need to increase bio->bi_cnt to avoid bio getting freed? */
}

void tier_make_request(struct request_queue *q, struct bio *parent_bio)
{
	int cpu;
	struct tier_device *dev = q->queuedata;
	struct bio_task *bt;
	int rw = bio_rw(parent_bio);

	atomic_set(&dev->wqlock, NORMAL_IO);
	down_read(&dev->qlock);

	if (rw == READA)
		rw = READ;

	BUG_ON(!dev || (rw != READ && rw != WRITE));
	if (unlikely(!dev->active))
		goto out;

	cpu = part_stat_lock();
	part_stat_inc(cpu, &dev->gd->part0, ios[rw]);
	part_stat_add(cpu, &dev->gd->part0, sectors[rw], 
		      bio_sectors(parent_bio));
	part_stat_unlock();

	/* increase aio_pending for each bio */
	atomic_inc(&dev->aio_pending);

	//3. handle bio when deregister happens.
	//4. handle meta data. need a workqueue to finish wait operations.

	if (unlikely(!parent_bio->bi_iter.bi_size)) {
		tier_dev_nodata(dev, parent_bio);
	} else {
		if (rw && (parent_bio->bi_rw & REQ_DISCARD)) {
			tier_dev_discard(dev, parent_bio);
			goto end_return;
		}

		bt = task_alloc(parent_bio, dev);

		if (rw)
			tiered_dev_write(bt, dev);
		else
			tiered_dev_read(bt, dev);
	}

	goto end_return;

out:
	bio_io_error(parent_bio);
end_return:
	atomic_set(&dev->wqlock, 0);
	up_read(&dev->qlock);
	return;
}

void tier_request_exit(void)
{
	if (bio_task_cache)
		kmem_cache_destroy(bio_task_cache);
}

int __init tier_request_init(void)
{
	bio_task_cache = KMEM_CACHE(bio_task, 0);
	if (!bio_task_cache)
		return -ENOMEM;

	return 0;
}
