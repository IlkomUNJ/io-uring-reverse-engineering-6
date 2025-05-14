// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/nospec.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "rsrc.h"
#include "filetable.h"
#include "alloc_cache.h"
#include "msg_ring.h"

/* All valid masks for MSG_RING */
#define IORING_MSG_RING_MASK		(IORING_MSG_RING_CQE_SKIP | \
					IORING_MSG_RING_FLAGS_PASS)

/* 
 * struct io_msg - Struktur data yang digunakan untuk menyimpan informasi terkait
 * pesan yang diproses dalam io_uring, seperti file sumber, file tujuan, dan data terkait.
 */
struct io_msg {
	struct file			*file;
	struct file			*src_file;
	struct callback_head		tw;
	u64 user_data;
	u32 len;
	u32 cmd;
	u32 src_fd;
	union {
		u32 dst_fd;
		u32 cqe_flags;
	};
	u32 flags;
};

/* 
 * io_double_unlock_ctx - Melepaskan kunci yang dipakai untuk mengunci konteks
 * uring yang ditentukan.
 */
static void io_double_unlock_ctx(struct io_ring_ctx *octx)
{
	mutex_unlock(&octx->uring_lock);
}

/* 
 * io_lock_external_ctx - Mengunci konteks eksternal dengan memperhatikan urutan
 * yang benar antara konteks yang terlibat. Jika tidak bisa mengunci, maka mengembalikan -EAGAIN.
 */
static int io_lock_external_ctx(struct io_ring_ctx *octx,
				unsigned int issue_flags)
{
	if (!(issue_flags & IO_URING_F_UNLOCKED)) {
		if (!mutex_trylock(&octx->uring_lock))
			return -EAGAIN;
		return 0;
	}
	mutex_lock(&octx->uring_lock);
	return 0;
}

/* 
 * io_msg_ring_cleanup - Membersihkan sumber daya yang terkait dengan pesan
 * setelah selesai diproses. Menutup file sumber jika ada.
 */
void io_msg_ring_cleanup(struct io_kiocb *req)
{
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);

	if (WARN_ON_ONCE(!msg->src_file))
		return;

	fput(msg->src_file);
	msg->src_file = NULL;
}

/* 
 * io_msg_need_remote - Memeriksa apakah pesan perlu diproses di konteks target yang
 * berbeda, tergantung pada apakah tugas selesai.
 */
static inline bool io_msg_need_remote(struct io_ring_ctx *target_ctx)
{
	return target_ctx->task_complete;
}

/* 
 * io_msg_tw_complete - Menangani penyelesaian tugas untuk pesan, mengirimkan
 * hasil tugas kembali ke konteks dan membersihkan sumber daya.
 */
static void io_msg_tw_complete(struct io_kiocb *req, io_tw_token_t tw)
{
	struct io_ring_ctx *ctx = req->ctx;

	io_add_aux_cqe(ctx, req->cqe.user_data, req->cqe.res, req->cqe.flags);
	if (spin_trylock(&ctx->msg_lock)) {
		if (io_alloc_cache_put(&ctx->msg_cache, req))
			req = NULL;
		spin_unlock(&ctx->msg_lock);
	}
	if (req)
		kmem_cache_free(req_cachep, req);
	percpu_ref_put(&ctx->refs);
}

/* 
 * io_msg_remote_post - Menyampaikan pesan untuk diproses secara remote jika konteks
 * pengirim tidak ada, mengembalikan -EOWNERDEAD jika gagal.
 */
static int io_msg_remote_post(struct io_ring_ctx *ctx, struct io_kiocb *req,
			      int res, u32 cflags, u64 user_data)
{
	if (!READ_ONCE(ctx->submitter_task)) {
		kmem_cache_free(req_cachep, req);
		return -EOWNERDEAD;
	}
	req->opcode = IORING_OP_NOP;
	req->cqe.user_data = user_data;
	io_req_set_res(req, res, cflags);
	percpu_ref_get(&ctx->refs);
	req->ctx = ctx;
	req->tctx = NULL;
	req->io_task_work.func = io_msg_tw_complete;
	io_req_task_work_add_remote(req, IOU_F_TWQ_LAZY_WAKE);
	return 0;
}

/* 
 * io_msg_get_kiocb - Mendapatkan objek kiocb untuk pesan, mengambilnya dari cache atau
 * mengalokasikan yang baru jika cache kosong.
 */
static struct io_kiocb *io_msg_get_kiocb(struct io_ring_ctx *ctx)
{
	struct io_kiocb *req = NULL;

	if (spin_trylock(&ctx->msg_lock)) {
		req = io_alloc_cache_get(&ctx->msg_cache);
		spin_unlock(&ctx->msg_lock);
		if (req)
			return req;
	}
	return kmem_cache_alloc(req_cachep, GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO);
}

/* 
 * io_msg_data_remote - Mengirimkan data pesan ke konteks target untuk diproses secara remote.
 */
static int io_msg_data_remote(struct io_ring_ctx *target_ctx,
			      struct io_msg *msg)
{
	struct io_kiocb *target;
	u32 flags = 0;

	target = io_msg_get_kiocb(target_ctx);
	if (unlikely(!target))
		return -ENOMEM;

	if (msg->flags & IORING_MSG_RING_FLAGS_PASS)
		flags = msg->cqe_flags;

	return io_msg_remote_post(target_ctx, target, msg->len, flags,
					msg->user_data);
}

/* 
 * __io_msg_ring_data - Menangani pemrosesan data dari pesan, memvalidasi dan
 * memutuskan apakah harus diproses secara lokal atau remote.
 */
static int __io_msg_ring_data(struct io_ring_ctx *target_ctx,
			      struct io_msg *msg, unsigned int issue_flags)
{
	u32 flags = 0;
	int ret;

	if (msg->src_fd || msg->flags & ~IORING_MSG_RING_FLAGS_PASS)
		return -EINVAL;
	if (!(msg->flags & IORING_MSG_RING_FLAGS_PASS) && msg->dst_fd)
		return -EINVAL;
	if (target_ctx->flags & IORING_SETUP_R_DISABLED)
		return -EBADFD;

	if (io_msg_need_remote(target_ctx))
		return io_msg_data_remote(target_ctx, msg);

	if (msg->flags & IORING_MSG_RING_FLAGS_PASS)
		flags = msg->cqe_flags;

	ret = -EOVERFLOW;
	if (target_ctx->flags & IORING_SETUP_IOPOLL) {
		if (unlikely(io_lock_external_ctx(target_ctx, issue_flags)))
			return -EAGAIN;
	}
	if (io_post_aux_cqe(target_ctx, msg->user_data, msg->len, flags))
		ret = 0;
	if (target_ctx->flags & IORING_SETUP_IOPOLL)
		io_double_unlock_ctx(target_ctx);
	return ret;
}

/* 
 * io_msg_ring_data - Fungsi utama yang memproses data pesan untuk io_uring.
 */
static int io_msg_ring_data(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *target_ctx = req->file->private_data;
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);

	return __io_msg_ring_data(target_ctx, msg, issue_flags);
}

/* 
 * io_msg_grab_file - Mengambil file sumber berdasarkan file descriptor yang diberikan
 * dalam pesan. Jika file tidak ditemukan, mengembalikan -EBADF.
 */
static int io_msg_grab_file(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_rsrc_node *node;
	int ret = -EBADF;

	io_ring_submit_lock(ctx, issue_flags);
	node = io_rsrc_node_lookup(&ctx->file_table.data, msg->src_fd);
	if (node) {
		msg->src_file = io_slot_file(node);
		if (msg->src_file)
			get_file(msg->src_file);
		req->flags |= REQ_F_NEED_CLEANUP;
		ret = 0;
	}
	io_ring_submit_unlock(ctx, issue_flags);
	return ret;
}

/* 
 * io_msg_install_complete - Menangani penyelesaian instalasi file dalam konteks
 * target dan mengirimkan hasilnya sebagai Completion Queue Entry (CQE).
 */
static int io_msg_install_complete(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *target_ctx = req->file->private_data;
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	struct file *src_file = msg->src_file;
	int ret;

	if (unlikely(io_lock_external_ctx(target_ctx, issue_flags)))
		return -EAGAIN;

	ret = __io_fixed_fd_install(target_ctx, src_file, msg->dst_fd);
	if (ret < 0)
		goto out_unlock;

	msg->src_file = NULL;
	req->flags &= ~REQ_F_NEED_CLEANUP;

	if (msg->flags & IORING_MSG_RING_CQE_SKIP)
		goto out_unlock;

	if (!io_post_aux_cqe(target_ctx, msg->user_data, ret, 0))
		ret = -EOVERFLOW;
out_unlock:
	io_double_unlock_ctx(target_ctx);
	return ret;
}

/* 
 * io_msg_tw_fd_complete - Menyelesaikan tugas kerja (task work) terkait pengelolaan
 * file descriptor untuk pesan, menangani kegagalan jika diperlukan.
 */
static void io_msg_tw_fd_complete(struct callback_head *head)
{
	struct io_msg *msg = container_of(head, struct io_msg, tw);
	struct io_kiocb *req = cmd_to_io_kiocb(msg);
	int ret = -EOWNERDEAD;

	if (!(current->flags & PF_EXITING))
		ret = io_msg_install_complete(req, IO_URING_F_UNLOCKED);
	if (ret < 0)
		req_set_fail(req);
	io_req_queue_tw_complete(req, ret);
}

/* 
 * io_msg_fd_remote - Menangani pengiriman file descriptor untuk pengolahan
 * pesan secara remote.
 */
static int io_msg_fd_remote(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->file->private_data;
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	struct task_struct *task = READ_ONCE(ctx->submitter_task);

	if (unlikely(!task))
		return -EOWNERDEAD;

	init_task_work(&msg->tw, io_msg_tw_fd_complete);
	if (task_work_add(task, &msg->tw, TWA_SIGNAL))
		return -EOWNERDEAD;

	return IOU_ISSUE_SKIP_COMPLETE;
}

/* 
 * io_msg_send_fd - Menangani pengiriman file descriptor pada pesan yang dikirim
 * melalui io_uring.
 */
static int io_msg_send_fd(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ring_ctx *target_ctx = req->file->private_data;
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	struct io_ring_ctx *ctx = req->ctx;

	if (msg->len)
		return -EINVAL;
	if (target_ctx == ctx)
		return -EINVAL;
	if (target_ctx->flags & IORING_SETUP_R_DISABLED)
		return -EBADFD;
	if (!msg->src_file) {
		int ret = io_msg_grab_file(req, issue_flags);
		if (unlikely(ret))
			return ret;
	}

	if (io_msg_need_remote(target_ctx))
		return io_msg_fd_remote(req);
	return io_msg_install_complete(req, issue_flags);
}

/* 
 * __io_msg_ring_prep - Menyiapkan data untuk pesan dengan membaca dan memvalidasi
 *
static int __io_msg_ring_prep(struct io_msg *msg, const struct io_uring_sqe *sqe)
{
	if (unlikely(sqe->buf_index || sqe->personality))
		return -EINVAL;

	msg->src_file = NULL;
	msg->user_data = READ_ONCE(sqe->off);
	msg->len = READ_ONCE(sqe->len);
	msg->cmd = READ_ONCE(sqe->addr);
	msg->src_fd = READ_ONCE(sqe->addr3);
	msg->dst_fd = READ_ONCE(sqe->file_index);
	msg->flags = READ_ONCE(sqe->msg_ring_flags);
	if (msg->flags & ~IORING_MSG_RING_MASK)
		return -EINVAL;

	return 0;
}

int io_msg_ring_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	return __io_msg_ring_prep(io_kiocb_to_cmd(req, struct io_msg), sqe);
}

int io_msg_ring(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_msg *msg = io_kiocb_to_cmd(req, struct io_msg);
	int ret;

	ret = -EBADFD;
	if (!io_is_uring_fops(req->file))
		goto done;

	switch (msg->cmd) {
	case IORING_MSG_DATA:
		ret = io_msg_ring_data(req, issue_flags);
		break;
	case IORING_MSG_SEND_FD:
		ret = io_msg_send_fd(req, issue_flags);
		break;
	default:
		ret = -EINVAL;
		break;
	}

done:
	if (ret < 0) {
		if (ret == -EAGAIN || ret == IOU_ISSUE_SKIP_COMPLETE)
			return ret;
		req_set_fail(req);
	}
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

int io_uring_sync_msg_ring(struct io_uring_sqe *sqe)
{
    // Inisialisasi struktur io_msg untuk menampung data pesan
    struct io_msg io_msg = { };
    int ret;

    // Mempersiapkan pesan dari SQE (Submission Queue Entry)
    ret = __io_msg_ring_prep(&io_msg, sqe);
    if (unlikely(ret)) // Jika terjadi error saat persiapan, langsung keluar dengan error
        return ret;

    /*
     * Hanya perintah IORING_MSG_DATA yang didukung, bukan IORING_MSG_SEND_FD
     * karena pengiriman file descriptor hanya masuk akal jika ada ring sumber
     * untuk mengirim file descriptor.
     */
    if (io_msg.cmd != IORING_MSG_DATA)
        return -EINVAL; // Jika perintah bukan IORING_MSG_DATA, return error invalid argument

    // Memeriksa apakah file descriptor yang diberikan dalam SQE valid
    CLASS(fd, f)(sqe->fd); // Mengakses file descriptor dari SQE
    if (fd_empty(f)) // Jika file descriptor kosong, return error bad file descriptor
        return -EBADF;
    if (!io_is_uring_fops(fd_file(f))) // Memeriksa apakah file descriptor terkait dengan io_uring fops
        return -EBADFD; // Jika tidak, return error bad file descriptor

    // Mengirimkan data melalui io_msg_ring_data ke target context yang sesuai
    return __io_msg_ring_data(fd_file(f)->private_data,
                               &io_msg, IO_URING_F_UNLOCKED); // Mengirim data dengan flag unlocked
}

