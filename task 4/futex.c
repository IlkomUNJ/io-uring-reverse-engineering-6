// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "../kernel/futex/futex.h"
#include "io_uring.h"
#include "alloc_cache.h"
#include "futex.h"

// Struktur yang digunakan untuk menyimpan data terkait futex
struct io_futex {
	struct file	*file; // File terkait
	union {
		u32 __user			*uaddr; // Alamat pengguna untuk futex
		struct futex_waitv __user	*uwaitv; // Alamat pengguna untuk futex vector
	};
	unsigned long	futex_val; // Nilai futex
	unsigned long	futex_mask; // Mask futex
	unsigned long	futexv_owned; // Futuxt vector yang dimiliki
	u32		futex_flags; // Flag futex
	unsigned int	futex_nr; // Jumlah futex dalam vector
	bool		futexv_unqueued; // Menyatakan apakah futexv telah di-queue
};

// Struktur data yang digunakan untuk menyimpan informasi futex untuk IO
struct io_futex_data {
	struct futex_q	q; // Antrian futex
	struct io_kiocb	*req; // Permintaan IO
};

// Maksimum jumlah cache yang dapat dialokasikan untuk futex
#define IO_FUTEX_ALLOC_CACHE_MAX	32

// Inisialisasi cache futex
bool io_futex_cache_init(struct io_ring_ctx *ctx)
{
	return io_alloc_cache_init(&ctx->futex_cache, IO_FUTEX_ALLOC_CACHE_MAX,
				sizeof(struct io_futex_data), 0);
}

// Menghapus cache futex
void io_futex_cache_free(struct io_ring_ctx *ctx)
{
	io_alloc_cache_free(&ctx->futex_cache, kfree);
}

// Menyelesaikan permintaan IO terkait futex
static void __io_futex_complete(struct io_kiocb *req, io_tw_token_t tw)
{
	req->async_data = NULL; // Hapus data asinkron
	hlist_del_init(&req->hash_node); // Hapus node dari hash table
	io_req_task_complete(req, tw); // Menyelesaikan task IO
}

// Menyelesaikan permintaan futex
static void io_futex_complete(struct io_kiocb *req, io_tw_token_t tw)
{
	struct io_ring_ctx *ctx = req->ctx;

	io_tw_lock(ctx, tw); // Mengunci IO ring
	io_cache_free(&ctx->futex_cache, req->async_data); // Membebaskan cache futex
	__io_futex_complete(req, tw); // Menyelesaikan permintaan futex
}

// Menyelesaikan permintaan futex vector
static void io_futexv_complete(struct io_kiocb *req, io_tw_token_t tw)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	struct futex_vector *futexv = req->async_data;

	io_tw_lock(req->ctx, tw); // Mengunci IO ring

	if (!iof->futexv_unqueued) {
		int res;

		res = futex_unqueue_multiple(futexv, iof->futex_nr); // Unqueue futex
		if (res != -1)
			io_req_set_res(req, res, 0); // Set hasil permintaan IO
	}

	kfree(req->async_data); // Membebaskan data asinkron
	req->flags &= ~REQ_F_ASYNC_DATA; // Menghapus flag data asinkron
	__io_futex_complete(req, tw); // Menyelesaikan permintaan futex
}

// Memastikan futex vector dimiliki
static bool io_futexv_claim(struct io_futex *iof)
{
	if (test_bit(0, &iof->futexv_owned) || 
	    test_and_set_bit_lock(0, &iof->futexv_owned)) // Mengunci futex
		return false;
	return true;
}

// Membatalkan permintaan futex
static bool __io_futex_cancel(struct io_kiocb *req)
{
	/* futex wake sudah dilakukan atau sedang diproses */
	if (req->opcode == IORING_OP_FUTEX_WAIT) {
		struct io_futex_data *ifd = req->async_data;

		if (!futex_unqueue(&ifd->q)) // Menghapus futex dari antrian
			return false;
		req->io_task_work.func = io_futex_complete; // Set fungsi untuk menyelesaikan task
	} else {
		struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);

		if (!io_futexv_claim(iof)) // Memastikan futex vector dimiliki
			return false;
		req->io_task_work.func = io_futexv_complete; // Set fungsi untuk menyelesaikan futex vector
	}

	hlist_del_init(&req->hash_node); // Menghapus node dari hash table
	io_req_set_res(req, -ECANCELED, 0); // Set hasil permintaan sebagai dibatalkan
	io_req_task_work_add(req); // Menambahkan pekerjaan task
	return true;
}

// Fungsi untuk membatalkan permintaan futex
int io_futex_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		    unsigned int issue_flags)
{
	return io_cancel_remove(ctx, cd, issue_flags, &ctx->futex_list, __io_futex_cancel);
}

// Fungsi untuk menghapus semua futex dari konteks
bool io_futex_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			 bool cancel_all)
{
	return io_cancel_remove_all(ctx, tctx, &ctx->futex_list, cancel_all, __io_futex_cancel);
}

// Mempersiapkan permintaan futex
int io_futex_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	u32 flags;

	if (unlikely(sqe->len || sqe->futex_flags || sqe->buf_index ||
		     sqe->file_index)) // Memeriksa parameter yang tidak valid
		return -EINVAL;

	iof->uaddr = u64_to_user_ptr(READ_ONCE(sqe->addr)); // Mengatur alamat futex
	iof->futex_val = READ_ONCE(sqe->addr2); // Mengatur nilai futex
	iof->futex_mask = READ_ONCE(sqe->addr3); // Mengatur mask futex
	flags = READ_ONCE(sqe->fd);

	if (flags & ~FUTEX2_VALID_MASK) // Memeriksa flag yang tidak valid
		return -EINVAL;

	iof->futex_flags = futex2_to_flags(flags); // Mengatur flag futex
	if (!futex_flags_valid(iof->futex_flags)) // Memeriksa validitas flag futex
		return -EINVAL;

	if (!futex_validate_input(iof->futex_flags, iof->futex_val) ||
	    !futex_validate_input(iof->futex_flags, iof->futex_mask)) // Memeriksa validitas nilai dan mask
		return -EINVAL;

	return 0;
}

// Fungsi untuk menangani wake futex vector
static void io_futex_wakev_fn(struct wake_q_head *wake_q, struct futex_q *q)
{
	struct io_kiocb *req = q->wake_data;
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);

	if (!io_futexv_claim(iof)) // Memastikan futex vector dimiliki
		return;
	if (unlikely(!__futex_wake_mark(q))) // Memeriksa status wake futex
		return;

	io_req_set_res(req, 0, 0); // Set hasil permintaan IO
	req->io_task_work.func = io_futexv_complete; // Set fungsi untuk menyelesaikan futex
	io_req_task_work_add(req); // Menambahkan pekerjaan task
}

// Mempersiapkan permintaan futex vector
int io_futexv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	struct futex_vector *futexv;
	int ret;

	/* No flags or mask supported for waitv */
	if (unlikely(sqe->fd || sqe->buf_index || sqe->file_index ||
		     sqe->addr2 || sqe->futex_flags || sqe->addr3)) // Memeriksa parameter yang tidak valid
		return -EINVAL;

	iof->uaddr = u64_to_user_ptr(READ_ONCE(sqe->addr)); // Mengatur alamat futex
	iof->futex_nr = READ_ONCE(sqe->len); // Mengatur jumlah futex dalam vector
	if (!iof->futex_nr || iof->futex_nr > FUTEX_WAITV_MAX) // Memeriksa jumlah futex yang valid
		return -EINVAL;

	futexv = kcalloc(iof->futex_nr, sizeof(*futexv), GFP_KERNEL); // Mengalokasikan memory untuk futex vector
	if (!futexv)
		return -ENOMEM;

	ret = futex_parse_waitv(futexv, iof->uwaitv, iof->futex_nr,
				io_futex_wakev_fn, req); // Mem-parsing futex vector
	if (ret) {
		kfree(futexv);
		return ret;
	}

	iof->futexv_owned = 0;
	iof->futexv_unqueued = 0;
	req->flags |= REQ_F_ASYNC_DATA; // Menandai data asinkron
	req->async_data = futexv;
	return 0;
}

// Fungsi untuk menangani wake futex
static void io_futex_wake_fn(struct wake_q_head *wake_q, struct futex_q *q)
{
	struct io_futex_data *ifd = container_of(q, struct io_futex_data, q);
	struct io_kiocb *req = ifd->req;

	if (unlikely(!__futex_wake_mark(q))) // Memeriksa status wake futex
		return;

	io_req_set_res(req, 0, 0); // Set hasil permintaan IO
	req->io_task_work.func = io_futex_complete; // Set fungsi untuk menyelesaikan permintaan
	io_req_task_work_add(req); // Menambahkan pekerjaan task
}

// Fungsi untuk menunggu futex vector
int io_futexv_wait(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	struct futex_vector *futexv = req->async_data;
	struct io_ring_ctx *ctx = req->ctx;
	int ret, woken = -1;

	io_ring_submit_lock(ctx, issue_flags); // Mengunci IO ring

	ret = futex_wait_multiple_setup(futexv, iof->futex_nr, &woken); // Menyiapkan futex untuk menunggu

	/*
	 * Error case, ret is < 0. Mark the request as failed.
	 */
	if (unlikely(ret < 0)) {
		io_ring_submit_unlock(ctx, issue_flags); // Membuka kunci IO ring
		req_set_fail(req); // Menandai permintaan gagal
		io_req_set_res(req, ret, 0); // Set hasil permintaan sebagai error
		kfree(futexv);
		req->async_data = NULL; // Menghapus data asinkron
		req->flags &= ~REQ_F_ASYNC_DATA; // Menghapus flag data asinkron
		return IOU_OK;
	}

	/*
	 * 0 return means that we successfully setup the waiters, and that
	 * nobody triggered a wakeup while we were doing so.
	 */
	if (!ret) {
		__set_current_state(TASK_RUNNING); // Menandai task sedang berjalan
		hlist_add_head(&req->hash_node, &ctx->futex_list); // Menambahkan task ke antrian futex
	} else {
		iof->futexv_unqueued = 1;
		if (woken != -1)
			io_req_set_res(req, woken, 0); // Set hasil jika futex sudah dibangunkan
	}

	io_ring_submit_unlock(ctx, issue_flags); // Membuka kunci IO ring
	return IOU_ISSUE_SKIP_COMPLETE;
}

// Fungsi untuk menunggu futex
int io_futex_wait(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_futex *iof = io_kiocb_to_cmd(req, struct io_futex);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_futex_data *ifd = NULL;
	struct futex_hash_bucket *hb;
	int ret;

	if (!iof->futex_mask) {
		ret =

