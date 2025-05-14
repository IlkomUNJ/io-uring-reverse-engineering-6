// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/poll.h>
#include <linux/vmalloc.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "opdef.h"
#include "kbuf.h"
#include "memmap.h"

/* BIDs are addressed by a 16-bit field in a CQE */
#define MAX_BIDS_PER_BGID (1 << 16)

/* Mapped buffer ring, return io_uring_buf from head */
#define io_ring_head_to_buf(br, head, mask)	&(br)->bufs[(head) & (mask)]

struct io_provide_buf {
	struct file			*file;  // File associated with buffer
	__u64				addr;  // Address of the buffer
	__u32				len;   // Length of the buffer
	__u32				bgid;  // Buffer group ID
	__u32				nbufs; // Number of buffers
	__u16				bid;   // Buffer ID
};

// Function to incrementally commit a buffer in the list
static bool io_kbuf_inc_commit(struct io_buffer_list *bl, int len)
{
	while (len) {
		struct io_uring_buf *buf;
		u32 this_len;

		buf = io_ring_head_to_buf(bl->buf_ring, bl->head, bl->mask);
		this_len = min_t(int, len, buf->len);
		buf->len -= this_len;
		if (buf->len) {
			buf->addr += this_len;
			return false;  // More data remains in the buffer
		}
		bl->head++;
		len -= this_len;
	}
	return true;  // All data committed
}

// Commit buffer list based on provided length and number of buffers
bool io_kbuf_commit(struct io_kiocb *req,
		    struct io_buffer_list *bl, int len, int nr)
{
	if (unlikely(!(req->flags & REQ_F_BUFFERS_COMMIT)))
		return true;

	req->flags &= ~REQ_F_BUFFERS_COMMIT;

	if (unlikely(len < 0))
		return true;
	if (bl->flags & IOBL_INC)
		return io_kbuf_inc_commit(bl, len);  // Commit incrementally
	bl->head += nr;  // Update the buffer list head after commit
	return true;
}

// Get the buffer list based on the buffer group ID (bgid)
static inline struct io_buffer_list *io_buffer_get_list(struct io_ring_ctx *ctx,
							unsigned int bgid)
{
	lockdep_assert_held(&ctx->uring_lock);  // Assert lock is held

	return xa_load(&ctx->io_bl_xa, bgid);  // Load buffer list from the context
}

// Add buffer list to the ring context and mark it as visible
static int io_buffer_add_list(struct io_ring_ctx *ctx,
			      struct io_buffer_list *bl, unsigned int bgid)
{
	bl->bgid = bgid;  // Set buffer group ID
	guard(mutex)(&ctx->mmap_lock);  // Lock for mmap operation
	return xa_err(xa_store(&ctx->io_bl_xa, bgid, bl, GFP_KERNEL));  // Store buffer list in the context
}

// Drop legacy buffer from request (free memory and reset)
void io_kbuf_drop_legacy(struct io_kiocb *req)
{
	if (WARN_ON_ONCE(!(req->flags & REQ_F_BUFFER_SELECTED)))
		return;
	req->buf_index = req->kbuf->bgid;
	req->flags &= ~REQ_F_BUFFER_SELECTED;
	kfree(req->kbuf);  // Free the selected buffer
	req->kbuf = NULL;  // Reset buffer pointer
}

// Recycle a legacy buffer to the buffer list and reset the request flags
bool io_kbuf_recycle_legacy(struct io_kiocb *req, unsigned issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer_list *bl;
	struct io_buffer *buf;

	io_ring_submit_lock(ctx, issue_flags);  // Lock for submit operation

	buf = req->kbuf;
	bl = io_buffer_get_list(ctx, buf->bgid);  // Get buffer list by group ID
	list_add(&buf->list, &bl->buf_list);  // Add buffer to the list
	req->flags &= ~REQ_F_BUFFER_SELECTED;  // Reset selected buffer flag
	req->buf_index = buf->bgid;  // Update buffer index

	io_ring_submit_unlock(ctx, issue_flags);  // Unlock after operation
	return true;
}

// Select the provided buffer from the list and update request
static void __user *io_provided_buffer_select(struct io_kiocb *req, size_t *len,
					      struct io_buffer_list *bl)
{
	if (!list_empty(&bl->buf_list)) {  // Check if the buffer list is not empty
		struct io_buffer *kbuf;

		kbuf = list_first_entry(&bl->buf_list, struct io_buffer, list);
		list_del(&kbuf->list);  // Remove buffer from the list
		if (*len == 0 || *len > kbuf->len)
			*len = kbuf->len;  // Adjust length if needed
		if (list_empty(&bl->buf_list))
			req->flags |= REQ_F_BL_EMPTY;  // Mark buffer list as empty
		req->flags |= REQ_F_BUFFER_SELECTED;  // Mark buffer as selected
		req->kbuf = kbuf;  // Assign the selected buffer
		req->buf_index = kbuf->bid;  // Set buffer ID
		return u64_to_user_ptr(kbuf->addr);  // Return buffer address to user
	}
	return NULL;  // Return NULL if no buffer is selected
}

// Select buffers from the provided buffer list based on given parameters
static int io_provided_buffers_select(struct io_kiocb *req, size_t *len,
				      struct io_buffer_list *bl,
				      struct iovec *iov)
{
	void __user *buf;

	buf = io_provided_buffer_select(req, len, bl);  // Select the buffer
	if (unlikely(!buf))
		return -ENOBUFS;  // Return error if no buffer available

	iov[0].iov_base = buf;  // Set buffer base in iovec
	iov[0].iov_len = *len;  // Set buffer length in iovec
	return 1;  // Return number of buffers selected
}

// Select buffer from the ring based on the issue flags
static void __user *io_ring_buffer_select(struct io_kiocb *req, size_t *len,
					  struct io_buffer_list *bl,
					  unsigned int issue_flags)
{
	struct io_uring_buf_ring *br = bl->buf_ring;
	__u16 tail, head = bl->head;
	struct io_uring_buf *buf;
	void __user *ret;

	tail = smp_load_acquire(&br->tail);  // Load the tail index atomically
	if (unlikely(tail == head))
		return NULL;  // Return NULL if no data available

	if (head + 1 == tail)
		req->flags |= REQ_F_BL_EMPTY;  // Mark buffer list as empty

	buf = io_ring_head_to_buf(br, head, bl->mask);  // Get buffer at head
	if (*len == 0 || *len > buf->len)
		*len = buf->len;  // Adjust length if needed
	req->flags |= REQ_F_BUFFER_RING | REQ_F_BUFFERS_COMMIT;  // Set flags for buffer commit
	req->buf_list = bl;  // Set buffer list
	req->buf_index = buf->bid;  // Set buffer ID
	ret = u64_to_user_ptr(buf->addr);  // Return buffer address to user

	if (issue_flags & IO_URING_F_UNLOCKED || !io_file_can_poll(req)) {
		io_kbuf_commit(req, bl, *len, 1);  // Commit buffer if necessary
		req->buf_list = NULL;  // Reset buffer list
	}
	return ret;
}

// General function to select buffer based on different flags and conditions
void __user *io_buffer_select(struct io_kiocb *req, size_t *len,
			      unsigned int issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer_list *bl;
	void __user *ret = NULL;

	io_ring_submit_lock(req->ctx, issue_flags);  // Lock for submit operation

	bl = io_buffer_get_list(ctx, req->buf_index);  // Get the buffer list
	if (likely(bl)) {
		if (bl->flags & IOBL_BUF_RING)
			ret = io_ring_buffer_select(req, len, bl, issue_flags);  // Select buffer from ring
		else
			ret = io_provided_buffer_select(req, len, bl);  // Select provided buffer
	}
	io_ring_submit_unlock(req->ctx, issue_flags);  // Unlock after operation
	return ret;
}

// Peek buffers from the ring and store in the provided buffer list
static int io_ring_buffers_peek(struct io_kiocb *req, struct buf_sel_arg *arg,
				struct io_buffer_list *bl)
{
	struct io_uring_buf_ring *br = bl->buf_ring;
	struct iovec *iov = arg->iovs;
	int nr_iovs = arg->nr_iovs;
	__u16 nr_avail, tail, head;
	struct io_uring_buf *buf;

	tail = smp_load_acquire(&br->tail);  // Load tail atomically
	head = bl->head;  // Get current head position
	nr_avail = min_t(__u16, tail - head, UIO_MAXIOV);  // Calculate available buffers
	if (unlikely(!nr_avail))
		return -ENOBUFS;  // Return error if no buffers available

	buf = io_ring_head_to_buf(br, head, bl->mask);  // Get the buffer at head
	if (arg->max_len) {
		u32 len = READ_ONCE(buf->len);
		size_t needed;

		if (unlikely(!len))
			return -ENOBUFS;  // Return error if buffer length is

		needed = (arg->max_len + len - 1) / len;
		needed = min_not_zero(needed, (size_t) PEEK_MAX_IMPORT);
		if (nr_avail > needed)
			nr_avail = needed;
	}

	/*
	 * only alloc a bigger array if we know we have data to map, eg not
	 * a speculative peek operation.
	 */
	if (arg->mode & KBUF_MODE_EXPAND && nr_avail > nr_iovs && arg->max_len) {
		iov = kmalloc_array(nr_avail, sizeof(struct iovec), GFP_KERNEL);
		if (unlikely(!iov))
			return -ENOMEM;
		if (arg->mode & KBUF_MODE_FREE)
			kfree(arg->iovs);
		arg->iovs = iov;
		nr_iovs = nr_avail;
	} else if (nr_avail < nr_iovs) {
		nr_iovs = nr_avail;
	}

	/* set it to max, if not set, so we can use it unconditionally */
	if (!arg->max_len)
		arg->max_len = INT_MAX;

	req->buf_index = buf->bid;
	do {
		u32 len = buf->len;

		/* truncate end piece, if needed, for non partial buffers */
		if (len > arg->max_len) {
			len = arg->max_len;
			if (!(bl->flags & IOBL_INC))
				buf->len = len;
		}

		iov->iov_base = u64_to_user_ptr(buf->addr);
		iov->iov_len = len;
		iov++;

		arg->out_len += len;
		arg->max_len -= len;
		if (!arg->max_len)
			break;

		buf = io_ring_head_to_buf(br, ++head, bl->mask);
	} while (--nr_iovs);

	if (head == tail)
		req->flags |= REQ_F_BL_EMPTY;

	req->flags |= REQ_F_BUFFER_RING;
	req->buf_list = bl;
	return iov - arg->iovs;
}

int io_buffers_select(struct io_kiocb *req, struct buf_sel_arg *arg,
		      unsigned int issue_flags)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer_list *bl;
	int ret = -ENOENT;

	io_ring_submit_lock(ctx, issue_flags);
	bl = io_buffer_get_list(ctx, req->buf_index);
	if (unlikely(!bl))
		goto out_unlock;

	if (bl->flags & IOBL_BUF_RING) {
		ret = io_ring_buffers_peek(req, arg, bl);
		/*
		 * Don't recycle these buffers if we need to go through poll.
		 * Nobody else can use them anyway, and holding on to provided
		 * buffers for a send/write operation would happen on the app
		 * side anyway with normal buffers. Besides, we already
		 * committed them, they cannot be put back in the queue.
		 */
		if (ret > 0) {
			req->flags |= REQ_F_BUFFERS_COMMIT | REQ_F_BL_NO_RECYCLE;
			io_kbuf_commit(req, bl, arg->out_len, ret);
		}
	} else {
		ret = io_provided_buffers_select(req, &arg->out_len, bl, arg->iovs);
	}
out_unlock:
	io_ring_submit_unlock(ctx, issue_flags);
	return ret;
}

int io_buffers_peek(struct io_kiocb *req, struct buf_sel_arg *arg)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer_list *bl;
	int ret;

	lockdep_assert_held(&ctx->uring_lock);

	bl = io_buffer_get_list(ctx, req->buf_index);
	if (unlikely(!bl))
		return -ENOENT;

	if (bl->flags & IOBL_BUF_RING) {
		ret = io_ring_buffers_peek(req, arg, bl);
		if (ret > 0)
			req->flags |= REQ_F_BUFFERS_COMMIT;
		return ret;
	}

	/* don't support multiple buffer selections for legacy */
	return io_provided_buffers_select(req, &arg->max_len, bl, arg->iovs);
}

// Function to commit the buffer ring and update the request structure
static inline bool __io_put_kbuf_ring(struct io_kiocb *req, int len, int nr)
{
	struct io_buffer_list *bl = req->buf_list;  // Get the buffer list associated with the request
	bool ret = true;

	// If there is a buffer list, commit the buffer
	if (bl) {
		ret = io_kbuf_commit(req, bl, len, nr);  // Commit the buffer to the request
		req->buf_index = bl->bgid;  // Set the buffer group ID for the request
	}

	req->flags &= ~REQ_F_BUFFER_RING;  // Clear the buffer ring flag
	return ret;
}

// Function to process the buffer ring and update the result code
unsigned int __io_put_kbufs(struct io_kiocb *req, int len, int nbufs)
{
	unsigned int ret;

	// Prepare the result code with a buffer flag and buffer group ID shifted
	ret = IORING_CQE_F_BUFFER | (req->buf_index << IORING_CQE_BUFFER_SHIFT);

	// If the request is not using a buffer ring, drop legacy buffers and return the result
	if (unlikely(!(req->flags & REQ_F_BUFFER_RING))) {
		io_kbuf_drop_legacy(req);
		return ret;
	}

	// If unable to commit buffer ring, mark the result as requiring more buffers
	if (!__io_put_kbuf_ring(req, len, nbufs))
		ret |= IORING_CQE_F_BUF_MORE;
	return ret;
}

// Function to remove buffers from the buffer list
static int __io_remove_buffers(struct io_ring_ctx *ctx,
			       struct io_buffer_list *bl, unsigned nbufs)
{
	unsigned i = 0;

	// If no buffers to remove, return 0
	if (!nbufs)
		return 0;

	// If buffer list is part of a ring, free the region and reset the list
	if (bl->flags & IOBL_BUF_RING) {
		i = bl->buf_ring->tail - bl->head;
		io_free_region(ctx, &bl->region);
		// Reset the buffer list to be empty
		INIT_LIST_HEAD(&bl->buf_list);
		bl->flags &= ~IOBL_BUF_RING;
		return i;
	}

	// Lock held to protect the io_buffers_cache
	lockdep_assert_held(&ctx->uring_lock);

	// Remove buffers from the list and free them until the specified number is reached
	while (!list_empty(&bl->buf_list)) {
		struct io_buffer *nxt;

		nxt = list_first_entry(&bl->buf_list, struct io_buffer, list);
		list_del(&nxt->list);
		kfree(nxt);

		if (++i == nbufs)
			return i;
		cond_resched();
	}

	return i;
}

// Function to free a buffer list and its buffers
static void io_put_bl(struct io_ring_ctx *ctx, struct io_buffer_list *bl)
{
	__io_remove_buffers(ctx, bl, -1U);  // Remove all buffers from the list
	kfree(bl);  // Free the buffer list itself
}

// Function to destroy buffers by iterating over buffer lists
void io_destroy_buffers(struct io_ring_ctx *ctx)
{
	struct io_buffer_list *bl;

	while (1) {
		unsigned long index = 0;

		// Scoped lock to safely access the buffer list
		scoped_guard(mutex, &ctx->mmap_lock) {
			bl = xa_find(&ctx->io_bl_xa, &index, ULONG_MAX, XA_PRESENT);
			if (bl)
				xa_erase(&ctx->io_bl_xa, bl->bgid);
		}
		if (!bl)
			break;
		io_put_bl(ctx, bl);  // Free the buffer list and its buffers
	}
}

// Function to destroy a specific buffer list
static void io_destroy_bl(struct io_ring_ctx *ctx, struct io_buffer_list *bl)
{
	// Scoped lock to safely access the buffer list and erase it
	scoped_guard(mutex, &ctx->mmap_lock)
		WARN_ON_ONCE(xa_erase(&ctx->io_bl_xa, bl->bgid) != bl);
	io_put_bl(ctx, bl);  // Free the buffer list
}

// Prepare function for removing buffers
int io_remove_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_provide_buf *p = io_kiocb_to_cmd(req, struct io_provide_buf);
	u64 tmp;

	// Validate the request's parameters
	if (sqe->rw_flags || sqe->addr || sqe->len || sqe->off ||
	    sqe->splice_fd_in)
		return -EINVAL;

	tmp = READ_ONCE(sqe->fd);
	if (!tmp || tmp > MAX_BIDS_PER_BGID)
		return -EINVAL;

	// Initialize the buffer information structure
	memset(p, 0, sizeof(*p));
	p->nbufs = tmp;
	p->bgid = READ_ONCE(sqe->buf_group);
	return 0;
}

// Function to remove buffers from a specific buffer group
int io_remove_buffers(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_provide_buf *p = io_kiocb_to_cmd(req, struct io_provide_buf);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer_list *bl;
	int ret = 0;

	io_ring_submit_lock(ctx, issue_flags);

	// Get the buffer list by group ID
	ret = -ENOENT;
	bl = io_buffer_get_list(ctx, p->bgid);
	if (bl) {
		ret = -EINVAL;
		// Check if buffer list can be modified
		if (!(bl->flags & IOBL_BUF_RING))
			ret = __io_remove_buffers(ctx, bl, p->nbufs);
	}
	io_ring_submit_unlock(ctx, issue_flags);
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

// Prepare function for providing buffers
int io_provide_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	unsigned long size, tmp_check;
	struct io_provide_buf *p = io_kiocb_to_cmd(req, struct io_provide_buf);
	u64 tmp;

	// Validate the request's parameters
	if (sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	tmp = READ_ONCE(sqe->fd);
	if (!tmp || tmp > MAX_BIDS_PER_BGID)
		return -E2BIG;
	p->nbufs = tmp;
	p->addr = READ_ONCE(sqe->addr);
	p->len = READ_ONCE(sqe->len);

	// Check for overflow in buffer size calculations
	if (check_mul_overflow((unsigned long)p->len, (unsigned long)p->nbufs,
				&size))
		return -EOVERFLOW;
	if (check_add_overflow((unsigned long)p->addr, size, &tmp_check))
		return -EOVERFLOW;

	// Check if the provided memory is valid
	size = (unsigned long)p->len * p->nbufs;
	if (!access_ok(u64_to_user_ptr(p->addr), size))
		return -EFAULT;

	// Validate the buffer group ID and offset
	p->bgid = READ_ONCE(sqe->buf_group);
	tmp = READ_ONCE(sqe->off);
	if (tmp > USHRT_MAX)
		return -E2BIG;
	if (tmp + p->nbufs > MAX_BIDS_PER_BGID)
		return -EINVAL;
	p->bid = tmp;
	return 0;
}

// Add buffers to the buffer list
static int io_add_buffers(struct io_ring_ctx *ctx, struct io_provide_buf *pbuf,
			  struct io_buffer_list *bl)
{
	struct io_buffer *buf;
	u64 addr = pbuf->addr;
	int i, bid = pbuf->bid;

	// Allocate and add buffers to the list
	for (i = 0; i < pbuf->nbufs; i++) {
		buf = kmalloc(sizeof(*buf), GFP_KERNEL_ACCOUNT);
		if (!buf)
			break;

		list_add_tail(&buf->list, &bl->buf_list);
		buf->addr = addr;
		buf->len = min_t(__u32, pbuf->len, MAX_RW_COUNT);
		buf->bid = bid;
		buf->bgid = pbuf->bgid;
		addr += pbuf->len;
		bid++;
		cond_resched();
	}

	return i ? 0 : -ENOMEM;
}

// Function to provide buffers for a request
int io_provide_buffers(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_provide_buf *p = io_kiocb_to_cmd(req, struct io_provide_buf);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_buffer_list *bl;
	int ret = 0;

	io_ring_submit_lock(ctx, issue_flags);

	// Get or create the buffer list for the buffer group ID
	bl = io_buffer_get_list(ctx, p->bgid);
	if (unlikely(!bl)) {
		bl = kzalloc(sizeof(*bl), GFP_KERNEL_ACCOUNT);
		if (!bl) {
			ret = -ENOMEM;
			goto err;
		}
		INIT_LIST_HEAD(&bl->buf_list);
		ret = io_buffer_add_list(ctx, bl, p->bgid);
		if (ret) {
			kfree(bl);
			goto err;
		}
	}

	// If the buffer list is part of a ring, return error
	if (bl->flags & IOBL_BUF_RING) {
		ret = -EINVAL;
		goto err;
	}

	// Add buffers to the list
	ret = io_add_buffers(ctx, p, bl);
err:
	io_ring_submit_unlock(ctx, issue_flags);

	// Handle error case by setting failure for the request
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

int io_provide_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
    // Memeriksa flag rw_flags dan splice_fd_in pada sqe
    if (sqe->rw_flags || sqe->splice_fd_in)
        return -EINVAL;

    // Membaca dan memvalidasi fd (file descriptor)
    tmp = READ_ONCE(sqe->fd);
    if (!tmp || tmp > MAX_BIDS_PER_BGID)
        return -E2BIG;
    p->nbufs = tmp;

    // Membaca dan memvalidasi alamat dan panjang buffer
    p->addr = READ_ONCE(sqe->addr);
    p->len = READ_ONCE(sqe->len);

    // Memastikan tidak terjadi overflow saat menghitung total ukuran buffer
    if (check_mul_overflow((unsigned long)p->len, (unsigned long)p->nbufs, &size))
        return -EOVERFLOW;
    if (check_add_overflow((unsigned long)p->addr, size, &tmp_check))
        return -EOVERFLOW;

    // Memeriksa apakah alamat buffer dapat diakses
    size = (unsigned long)p->len * p->nbufs;
    if (!access_ok(u64_to_user_ptr(p->addr), size))
        return -EFAULT;

    // Membaca buffer group ID dan validasi offset buffer
    p->bgid = READ_ONCE(sqe->buf_group);
    tmp = READ_ONCE(sqe->off);
    if (tmp > USHRT_MAX)
        return -E2BIG;
    if (tmp + p->nbufs > MAX_BIDS_PER_BGID)
        return -EINVAL;
    p->bid = tmp;
    return 0;
}

static int io_add_buffers(struct io_ring_ctx *ctx, struct io_provide_buf *pbuf, struct io_buffer_list *bl)
{
    // Menambahkan buffer baru ke dalam buffer list
    struct io_buffer *buf;
    u64 addr = pbuf->addr;
    int i, bid = pbuf->bid;

    // Mengalokasikan memori untuk setiap buffer dan menambahkannya ke dalam list
    for (i = 0; i < pbuf->nbufs; i++) {
        buf = kmalloc(sizeof(*buf), GFP_KERNEL_ACCOUNT);
        if (!buf)
            break;

        list_add_tail(&buf->list, &bl->buf_list);
        buf->addr = addr;
        buf->len = min_t(__u32, pbuf->len, MAX_RW_COUNT);
        buf->bid = bid;
        buf->bgid = pbuf->bgid;
        addr += pbuf->len;
        bid++;
        cond_resched();
    }

    return i ? 0 : -ENOMEM;
}

int io_provide_buffers(struct io_kiocb *req, unsigned int issue_flags)
{
    // Mengunci konteks ring sebelum memulai operasi
    struct io_provide_buf *p = io_kiocb_to_cmd(req, struct io_provide_buf);
    struct io_ring_ctx *ctx = req->ctx;
    struct io_buffer_list *bl;
    int ret = 0;

    io_ring_submit_lock(ctx, issue_flags);

    // Mengambil buffer list berdasarkan bgid
    bl = io_buffer_get_list(ctx, p->bgid);
    if (unlikely(!bl)) {
        bl = kzalloc(sizeof(*bl), GFP_KERNEL_ACCOUNT);
        if (!bl) {
            ret = -ENOMEM;
            goto err;
        }
        INIT_LIST_HEAD(&bl->buf_list);
        ret = io_buffer_add_list(ctx, bl, p->bgid);
        if (ret) {
            kfree(bl);
            goto err;
        }
    }

    // Memeriksa apakah buffer ring dapat ditambahkan
    if (bl->flags & IOBL_BUF_RING) {
        ret = -EINVAL;
        goto err;
    }

    // Menambahkan buffer ke dalam list
    ret = io_add_buffers(ctx, p, bl);
err:
    // Melepaskan kunci setelah operasi selesai
    io_ring_submit_unlock(ctx, issue_flags);

    if (ret < 0)
        req_set_fail(req);
    io_req_set_res(req, ret, 0);
    return IOU_OK;
}

int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)
{
    // Mendaftarkan buffer ring yang terkait dengan io_uring
    struct io_uring_buf_reg reg;
    struct io_buffer_list *bl, *free_bl = NULL;
    struct io_uring_region_desc rd;
    struct io_uring_buf_ring *br;
    unsigned long mmap_offset;
    unsigned long ring_size;
    int ret;

    lockdep_assert_held(&ctx->uring_lock);

    // Menyalin informasi registrasi dari pengguna
    if (copy_from_user(&reg, arg, sizeof(reg)))
        return -EFAULT;

    // Memvalidasi data registrasi
    if (reg.resv[0] || reg.resv[1] || reg.resv[2])
        return -EINVAL;
    if (reg.flags & ~(IOU_PBUF_RING_MMAP | IOU_PBUF_RING_INC))
        return -EINVAL;
    if (!is_power_of_2(reg.ring_entries))
        return -EINVAL;
    if (reg.ring_entries >= 65536)
        return -EINVAL;

    // Memeriksa apakah buffer group sudah ada
    bl = io_buffer_get_list(ctx, reg.bgid);
    if (bl) {
        if (bl->flags & IOBL_BUF_RING || !list_empty(&bl->buf_list))
            return -EEXIST;
        io_destroy_bl(ctx, bl);
    }

    // Alokasi memori untuk buffer list baru
    free_bl = bl = kzalloc(sizeof(*bl), GFP_KERNEL);
    if (!bl)
        return -ENOMEM;

    // Mengatur offset mmap dan ukuran ring
    mmap_offset = (unsigned long)reg.bgid << IORING_OFF_PBUF_SHIFT;
    ring_size = flex_array_size(br, bufs, reg.ring_entries);

    // Membuat region memori untuk buffer ring
    memset(&rd, 0, sizeof(rd));
    rd.size = PAGE_ALIGN(ring_size);
    if (!(reg.flags & IOU_PBUF_RING_MMAP)) {
        rd.user_addr = reg.ring_addr;
        rd.flags |= IORING_MEM_REGION_TYPE_USER;
    }
    ret = io_create_region_mmap_safe(ctx, &bl->region, &rd, mmap_offset);
    if (ret)
        goto fail;
    br = io_region_get_ptr(&bl->region);

    // Memeriksa keselarasan memori untuk platform yang memerlukan warna SHM
    #ifdef SHM_COLOUR
    if (!(reg.flags & IOU_PBUF_RING_MMAP) &&
        ((reg.ring_addr | (unsigned long)br) & (SHM_COLOUR - 1))) {
        ret = -EINVAL;
        goto fail;
    }
    #endif

    // Mengatur informasi buffer ring
    bl->nr_entries = reg.ring_entries;
    bl->mask = reg.ring_entries - 1;
    bl->flags |= IOBL_BUF_RING;
    bl->buf_ring = br;
    if (reg.flags & IOU_PBUF_RING_INC)
        bl->flags |= IOBL_INC;

    // Menambahkan buffer list ke dalam konteks
    io_buffer_add_list(ctx, bl, reg.bgid);
    return 0;

fail:
    // Menangani kesalahan alokasi dan membersihkan memori yang digunakan
    io_free_region(ctx, &bl->region);
    kfree(free_bl);
    return ret;
}

int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)
{
    // Membatalkan pendaftaran buffer ring yang terkait dengan io_uring
    struct io_uring_buf_reg reg;
    struct io_buffer_list *bl;

    lockdep_assert_held(&ctx->uring_lock);

    // Menyalin informasi pembatalan pendaftaran dari pengguna
    if (copy_from_user(&reg, arg, sizeof(reg)))
        return -EFAULT;
    if (reg.resv[0] || reg.resv[1] || reg.resv[2])
        return -EINVAL;
    if (reg.flags)
        return -EINVAL;

    // Mencari buffer list yang terdaftar berdasarkan bgid
    bl = io_buffer_get_list(ctx, reg.bgid);
    if (!bl)
        return -ENOENT;
    if (!(bl->flags & IOBL_BUF_RING))
        return -EINVAL;

    // Menghapus buffer list dari struktur data yang ada
    scoped_guard(mutex, &ctx->mmap_lock)
        xa_erase(&ctx->io_bl_xa, bl->bgid);

    // Menghapus dan membebaskan buffer list
    io_put_bl(ctx, bl);
    return 0;
}

int io_register_pbuf_status(struct io_ring_ctx *ctx, void __user *arg)
{
    // Mendaftarkan status buffer ring ke dalam io_uring
    struct io_uring_buf_status buf_status;
    struct io_buffer_list *bl;
    int i;

    // Menyalin status buffer dari pengguna
    if (copy_from_user(&buf_status, arg, sizeof(buf_status)))
        return -EFAULT;

    // Memvalidasi data status buffer
    for (i = 0; i < ARRAY_SIZE(buf_status.resv); i++)
        if (buf_status.resv[i])
            return -EINVAL;

    // Mencari buffer list berdasarkan buf_group
    bl = io_buffer_get_list(ctx, buf_status.buf_group);
    if (!bl)
        return -ENOENT;
    if (!(bl->flags & IOBL_BUF_RING))
        return -EINVAL;

    // Menyalin status buffer ke pengguna
    buf_status.head = bl->head;
    if (copy_to_user(arg, &buf_status, sizeof(buf_status)))
        return -EFAULT;

    return 0;
}


struct io_mapped_region *io_pbuf_get_region(struct io_ring_ctx *ctx, unsigned int bgid)
{
    // Memastikan mmap_lock sudah dipegang sebelum mengakses buffer list
    lockdep_assert_held(&ctx->mmap_lock);

    // Mencari buffer list berdasarkan bgid di dalam struktur io_bl_xa
    bl = xa_load(&ctx->io_bl_xa, bgid);
    
    // Memeriksa apakah buffer list ada dan memiliki flag IOBL_BUF_RING
    if (!bl || !(bl->flags & IOBL_BUF_RING))
        return NULL;
    
    // Mengembalikan pointer ke region yang terhubung dengan buffer list
    return &bl->region;
}

