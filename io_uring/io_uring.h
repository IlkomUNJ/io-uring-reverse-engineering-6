#ifndef IOU_CORE_H
#define IOU_CORE_H

#include <linux/errno.h>
#include <linux/lockdep.h>
#include <linux/resume_user_mode.h>
#include <linux/kasan.h>
#include <linux/poll.h>
#include <linux/io_uring_types.h>
#include <uapi/linux/eventpoll.h>
#include "alloc_cache.h"
#include "io-wq.h"
#include "slist.h"
#include "filetable.h"
#include "opdef.h"

#ifndef CREATE_TRACE_POINTS
#include <trace/events/io_uring.h>
#endif

/*
 * iou_core.h - Header utama untuk infrastruktur inti io_uring
 *
 * File ini mendefinisikan struktur, enum, dan fungsi utilitas penting
 * yang digunakan untuk manajemen antrian, penjadwalan, serta penyelesaian
 * operasi asynchronous dalam io_uring.
 */

...

enum {
	IOU_OK = 0, /* deprecated, gunakan IOU_COMPLETE */
	IOU_COMPLETE = 0,

	/*
	 * IOU_ISSUE_SKIP_COMPLETE menandakan bahwa permintaan belum selesai
	 * dan akan diselesaikan kemudian (ditunda).
	 */
	IOU_ISSUE_SKIP_COMPLETE = -EIOCBQUEUED,

	/*
	 * Permintaan perlu dicoba kembali. Bisa dilakukan langsung, atau
	 * ditangani oleh thread pekerja jika operasi bersifat blocking.
	 */
	IOU_RETRY = -EAGAIN,

	/*
	 * Permintaan perlu dijadwalkan ulang sebagai task_work.
	 */
	IOU_REQUEUE = -3072,
};

/*
 * Struktur untuk manajemen thread yang sedang menunggu hasil (CQE).
 */
struct io_wait_queue {
	...
};

/*
 * Mengecek apakah antrian CQ memiliki cukup item atau timeout telah terjadi,
 * untuk memutuskan apakah thread pengguna perlu dibangunkan.
 */
static inline bool io_should_wake(struct io_wait_queue *iowq) { ... }

/* 
 * Menghitung ukuran buffer ring berdasarkan parameter SQ dan CQ.
 */
unsigned long rings_size(unsigned int flags, unsigned int sq_entries,
                         unsigned int cq_entries, size_t *sq_offset);

/*
 * Mengisi parameter awal untuk inisialisasi io_uring.
 */
int io_uring_fill_params(unsigned entries, struct io_uring_params *p);

/*
 * Refill cache CQE jika diperlukan.
 */
bool io_cqe_cache_refill(struct io_ring_ctx *ctx, bool overflow);

/*
 * Menjalankan semua pekerjaan task_work yang tertunda dan menangani sinyal.
 */
int io_run_task_work_sig(struct io_ring_ctx *ctx);

/*
 * Menandai permintaan tertunda gagal dijalankan.
 */
void io_req_defer_failed(struct io_kiocb *req, s32 res);

/*
 * Menambahkan Completion Queue Entry (CQE) tambahan secara asinkron.
 */
bool io_post_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags);
void io_add_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags);

/*
 * Menyelesaikan permintaan dan memasukkan hasil ke ring.
 */
bool io_req_post_cqe(struct io_kiocb *req, s32 res, u32 cflags);

/*
 * Mengirim semua completion yang tertunda ke CQ.
 */
void __io_commit_cqring_flush(struct io_ring_ctx *ctx);

/*
 * Mengambil file berdasarkan descriptor dari tabel file pengguna.
 */
struct file *io_file_get_normal(struct io_kiocb *req, int fd);
struct file *io_file_get_fixed(struct io_kiocb *req, int fd, unsigned issue_flags);

/*
 * Menambahkan task_work ke antrian untuk eksekusi di masa mendatang.
 */
void __io_req_task_work_add(struct io_kiocb *req, unsigned flags);
void io_req_task_work_add_remote(struct io_kiocb *req, unsigned flags);
void io_req_task_queue(struct io_kiocb *req);
void io_req_task_complete(struct io_kiocb *req, io_tw_token_t tw);
void io_req_task_queue_fail(struct io_kiocb *req, int ret);
void io_req_task_submit(struct io_kiocb *req, io_tw_token_t tw);

/*
 * Menjalankan task_work dari list lokal.
 */
struct llist_node *io_handle_tw_list(struct llist_node *node, unsigned int *count, unsigned int max_entries);

/*
 * Menjalankan pekerjaan task_work untuk konteks task tertentu.
 */
struct llist_node *tctx_task_work_run(struct io_uring_task *tctx, unsigned int max_entries, unsigned int *count);
void tctx_task_work(struct callback_head *cb);

/*
 * Membatalkan semua request aktif dalam ring.
 */
__cold void io_uring_cancel_generic(bool cancel_all, struct io_sq_data *sqd);

/*
 * Mengalokasikan konteks io_uring untuk task.
 */
int io_uring_alloc_task_context(struct task_struct *task, struct io_ring_ctx *ctx);

/*
 * Menambahkan file ke dalam tabel file terdaftar.
 */
int io_ring_add_registered_file(struct io_uring_task *tctx, struct file *file, int start, int end);

/*
 * Menempatkan request ke dalam workqueue io_wq.
 */
void io_req_queue_iowq(struct io_kiocb *req);

/*
 * Menangani permintaan POLL (monitoring event IO).
 */
int io_poll_issue(struct io_kiocb *req, io_tw_token_t tw);

/*
 * Submit SQE ke dalam io_uring.
 */
int io_submit_sqes(struct io_ring_ctx *ctx, unsigned int nr);

/*
 * Melakukan polling IO (iopoll).
 */
int io_do_iopoll(struct io_ring_ctx *ctx, bool force_nonspin);

/*
 * Mengirim completion yang tertunda secara paksa.
 */
void __io_submit_flush_completions(struct io_ring_ctx *ctx);

/*
 * Menghapus dan mengembalikan memori kerja dari io_wq.
 */
struct io_wq_work *io_wq_free_work(struct io_wq_work *work);

/*
 * Submit pekerjaan io_wq.
 */
void io_wq_submit_work(struct io_wq_work *work);

/*
 * Mengembalikan memori request ke cache.
 */
void io_free_req(struct io_kiocb *req);

/*
 * Mengantrikan permintaan berikutnya dalam rangkaian.
 */
void io_queue_next(struct io_kiocb *req);

/*
 * Mengisi kembali referensi untuk task io_uring.
 */
void io_task_refs_refill(struct io_uring_task *tctx);

/*
 * Memeriksa apakah permintaan cocok dengan task dan bisa dibatalkan.
 */
bool io_match_task_safe(struct io_kiocb *head, struct io_uring_task *tctx, bool cancel_all);

/*
 * Mengaktifkan antrian POLL yang tertunda.
 */
void io_activate_pollwq(struct io_ring_ctx *ctx);

/*
 * Helper-inline lainnya menyediakan utilitas penting untuk manajemen:
 * - locking (mutex, spinlock)
 * - pencatatan hasil
 * - buffer alloc async
 * - pembuatan dan penanganan CQE
 * - pending work
 * - refill permintaan
 * - wakening antrian
 */

...

/*
 * Memeriksa apakah ada pekerjaan yang perlu dijalankan dari task lokal.
 */
static inline bool io_local_work_pending(struct io_ring_ctx *ctx) { ... }

/*
 * Memeriksa apakah ada pekerjaan task_work yang perlu dijalankan.
 */
static inline bool io_task_work_pending(struct io_ring_ctx *ctx) { ... }

/*
 * Menjalankan task_work yang tertunda dan menyelesaikan resume user mode.
 */
static inline int io_run_task_work(void) { ... }

...

/*
 * Mendefinisikan ukuran SQE berdasarkan flag IORING_SETUP_SQE128.
 */
static inline size_t uring_sqe_size(struct io_ring_ctx *ctx) 
{
	if (ctx->flags & IORING_SETUP_SQE128)
		return 2 * sizeof(struct io_uring_sqe);
	return sizeof(struct io_uring_sqe);
}

// Fungsi ini memeriksa apakah file yang terkait dengan I/O request dapat dipolling.
// Jika flag REQ_F_CAN_POLL sudah diset, maka langsung mengembalikan true.
// Jika tidak, akan memeriksa apakah file tersebut bisa dipolling menggunakan fungsi file_can_poll.
// Jika bisa, flag REQ_F_CAN_POLL akan diset dan mengembalikan true.
static inline bool io_file_can_poll(struct io_kiocb *req)
{
    if (req->flags & REQ_F_CAN_POLL)
        return true;  // Sudah dapat dipolling, langsung return true
    if (req->file && file_can_poll(req->file)) {  // Periksa apakah file bisa dipolling
        req->flags |= REQ_F_CAN_POLL;  // Set flag REQ_F_CAN_POLL agar tidak perlu memeriksa lagi di masa depan
        return true;  // File dapat dipolling
    }
    return false;  // File tidak bisa dipolling
}

// Fungsi ini mendapatkan waktu saat ini berdasarkan konteks io_ring_ctx.
// Jika clockid adalah CLOCK_MONOTONIC, waktu akan diambil menggunakan ktime_get().
// Jika tidak, waktu akan diambil dengan offset menggunakan ktime_get_with_offset.
static inline ktime_t io_get_time(struct io_ring_ctx *ctx)
{
    if (ctx->clockid == CLOCK_MONOTONIC)
        return ktime_get();  // Gunakan ktime_get() untuk CLOCK_MONOTONIC

    return ktime_get_with_offset(ctx->clock_offset);  // Gunakan offset jika bukan CLOCK_MONOTONIC
}

// Enum yang digunakan untuk memeriksa kondisi overflow atau dropped pada completion queue
enum {
    IO_CHECK_CQ_OVERFLOW_BIT,  // Bit untuk overflow pada completion queue
    IO_CHECK_CQ_DROPPED_BIT,   // Bit untuk dropped pada completion queue
};

// Fungsi ini memeriksa apakah ada pekerjaan yang harus dilakukan di io_ring_ctx.
// Memeriksa apakah ada bit overflow pada completion queue (IO_CHECK_CQ_OVERFLOW_BIT),
// atau apakah ada pekerjaan lokal yang pending (io_local_work_pending).
static inline bool io_has_work(struct io_ring_ctx *ctx)
{
    return test_bit(IO_CHECK_CQ_OVERFLOW_BIT, &ctx->check_cq) ||  // Periksa apakah ada overflow pada CQ
           io_local_work_pending(ctx);  // Periksa pekerjaan lokal yang pending
}

#endif
