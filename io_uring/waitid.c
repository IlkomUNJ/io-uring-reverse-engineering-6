// SPDX-License-Identifier: GPL-2.0
/*
 * Support for async notification of waitid
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/compat.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "cancel.h"
#include "waitid.h"
#include "../kernel/exit.h"

static void io_waitid_cb(struct io_kiocb *req, io_tw_token_t tw);

/*
 * Flag dan mask untuk manajemen referensi io_waitid
 */
#define IO_WAITID_CANCEL_FLAG	BIT(31)               /* Menandai permintaan telah dibatalkan */
#define IO_WAITID_REF_MASK	GENMASK(30, 0)        /* Mask untuk hitungan referensi */

/*
 * struct io_waitid - Struktur untuk menangani operasi waitid() di io_uring
 * @file: Pointer ke file yang terkait
 * @which: Jenis entitas (P_PID, P_PGID, dll) yang ditunggu
 * @upid: PID pengguna yang akan ditunggu
 * @options: Opsi waitid (WEXITED, WNOHANG, dll)
 * @refs: Referensi atomik, digunakan untuk sinkronisasi dan pembatalan
 * @head: Antrian tunggu untuk proses anak
 * @infop: Pointer ke lokasi hasil struct siginfo di ruang pengguna
 * @info: Informasi hasil waitid, diisi oleh kernel
 */
struct io_waitid {
	struct file *file;
	int which;
	pid_t upid;
	int options;
	atomic_t refs;
	struct wait_queue_head *head;
	struct siginfo __user *infop;
	struct waitid_info info;
};

/*
 * io_waitid_free - Membebaskan memori async_data dan mengurangi referensi PID
 * @req: Permintaan io_uring yang berkaitan
 *
 * Fungsi ini digunakan setelah operasi waitid selesai atau dibatalkan,
 * untuk membersihkan sumber daya terkait.
 */
static void io_waitid_free(struct io_kiocb *req)
{
	struct io_waitid_async *iwa = req->async_data;

	put_pid(iwa->wo.wo_pid);
	kfree(req->async_data);
	req->async_data = NULL;
	req->flags &= ~REQ_F_ASYNC_DATA;
}

/*
 * io_waitid_compat_copy_si - Menyalin hasil waitid ke siginfo (mode 32-bit)
 * @iw: Pointer ke struktur waitid internal
 * @signo: Sinyal yang akan ditulis ke siginfo
 *
 * Digunakan untuk sistem dengan ABI kompatibel 32-bit.
 *
 * Return: true jika sukses, false jika gagal (mis. kesalahan akses user).
 */
static bool io_waitid_compat_copy_si(struct io_waitid *iw, int signo)
{
	struct compat_siginfo __user *infop;
	bool ret;

	infop = (struct compat_siginfo __user *) iw->infop;

	if (!user_write_access_begin(infop, sizeof(*infop)))
		return false;

	unsafe_put_user(signo, &infop->si_signo, Efault);
	unsafe_put_user(0, &infop->si_errno, Efault);
	unsafe_put_user(iw->info.cause, &infop->si_code, Efault);
	unsafe_put_user(iw->info.pid, &infop->si_pid, Efault);
	unsafe_put_user(iw->info.uid, &infop->si_uid, Efault);
	unsafe_put_user(iw->info.status, &infop->si_status, Efault);
	ret = true;
done:
	user_write_access_end();
	return ret;
Efault:
	ret = false;
	goto done;
}

/*
 * io_waitid_copy_si - Menyalin hasil waitid ke siginfo (mode native atau compat)
 * @req: Permintaan io_uring yang berkaitan
 * @signo: Sinyal untuk diisi ke siginfo
 *
 * Fungsi ini akan mendeteksi ABI pengguna dan menyalin hasilnya dengan cara yang sesuai.
 *
 * Return: true jika sukses, false jika gagal.
 */
static bool io_waitid_copy_si(struct io_kiocb *req, int signo)
{
	struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);
	bool ret;

	if (!iw->infop)
		return true;

	if (io_is_compat(req->ctx))
		return io_waitid_compat_copy_si(iw, signo);

	if (!user_write_access_begin(iw->infop, sizeof(*iw->infop)))
		return false;

	unsafe_put_user(signo, &iw->infop->si_signo, Efault);
	unsafe_put_user(0, &iw->infop->si_errno, Efault);
	unsafe_put_user(iw->info.cause, &iw->infop->si_code, Efault);
	unsafe_put_user(iw->info.pid, &iw->infop->si_pid, Efault);
	unsafe_put_user(iw->info.uid, &iw->infop->si_uid, Efault);
	unsafe_put_user(iw->info.status, &iw->infop->si_status, Efault);
	ret = true;
done:
	user_write_access_end();
	return ret;
Efault:
	ret = false;
	goto done;
}

/*
 * io_waitid_finish - Menyelesaikan permintaan waitid dan menyalin hasil ke userspace
 * @req: Permintaan io_uring
 * @ret: Nilai hasil dari waitid kernel
 *
 * Fungsi ini akan menyalin hasil siginfo dan membersihkan sumber daya.
 *
 * Return: 0 jika sukses, atau error code.
 */
static int io_waitid_finish(struct io_kiocb *req, int ret)
{
	int signo = 0;

	if (ret > 0) {
		signo = SIGCHLD;
		ret = 0;
	}

	if (!io_waitid_copy_si(req, signo))
		ret = -EFAULT;

	io_waitid_free(req);
	return ret;
}

/*
 * io_waitid_complete - Menyelesaikan permintaan waitid dan menyetel hasilnya
 * @req: Permintaan io_uring
 * @ret: Nilai hasil dari waitid kernel
 *
 * Fungsi ini akan dipanggil saat permintaan selesai atau dibatalkan.
 */
static void io_waitid_complete(struct io_kiocb *req, int ret)
{
	struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);

	/* Pastikan masih ada referensi aktif sebelum menyelesaikan */
	WARN_ON_ONCE(!(atomic_read(&iw->refs) & IO_WAITID_REF_MASK));

	lockdep_assert_held(&req->ctx->uring_lock);

	hlist_del_init(&req->hash_node);

	ret = io_waitid_finish(req, ret);
	if (ret < 0)
		req_set_fail(req);

	io_req_set_res(req, ret, 0);
}

/*
 * __io_waitid_cancel - Membatalkan permintaan waitid jika masih aktif
 * @req: Permintaan io_uring
 *
 * Menandai permintaan sebagai dibatalkan, dan jika belum ada thread lain
 * yang menyelesaikannya, akan menghapus dari waitqueue dan menyelesaikannya
 * dengan status -ECANCELED.
 *
 * Return: true jika berhasil membatalkan, false jika sudah diambil alih.
 */
static bool __io_waitid_cancel(struct io_kiocb *req)
{
	struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);
	struct io_waitid_async *iwa = req->async_data;

	/* Tandai permintaan sebagai dibatalkan */
	atomic_or(IO_WAITID_CANCEL_FLAG, &iw->refs);

	/* Ambil kepemilikan jika belum ada yang menyelesaikan */
	if (atomic_fetch_inc(&iw->refs) & IO_WAITID_REF_MASK)
		return false;

	spin_lock_irq(&iw->head->lock);
	list_del_init(&iwa->wo.child_wait.entry);
	spin_unlock_irq(&iw->head->lock);

	io_waitid_complete(req, -ECANCELED);
	io_req_queue_tw_complete(req, -ECANCELED);
	return true;
}

/*
 * io_waitid_cancel - Mencoba membatalkan permintaan waitid tertentu
 * @ctx: Konteks io_uring
 * @cd: Data pembatalan (berisi user_data atau file descriptor)
 * @issue_flags: Flag yang relevan untuk pembatalan
 *
 * Return: 0 jika dibatalkan, -ENOENT jika tidak ditemukan, atau error lain.
 */
int io_waitid_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags)
{
	return io_cancel_remove(ctx, cd, issue_flags, &ctx->waitid_list, __io_waitid_cancel);
}

/*
 * io_waitid_remove_all - Menghapus semua permintaan waitid aktif untuk sebuah task
 * @ctx: Konteks io_uring
 * @tctx: Konteks task pengguna
 * @cancel_all: Jika true, batalkan semuanya tanpa memeriksa user_data
 *
 * Return: true jika ada permintaan yang dihapus, false jika tidak ada.
 */
bool io_waitid_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  bool cancel_all)
{
	return io_cancel_remove_all(ctx, tctx, &ctx->waitid_list, cancel_all, __io_waitid_cancel);
}

/*
 * io_waitid_drop_issue_ref - Melepas referensi awal setelah percobaan awal __do_wait
 * @req: Permintaan io_uring
 *
 * Jika referensi terakhir dilepas dan bangun telah terjadi, maka antrikan task_work
 * untuk menyelesaikan permintaan.
 *
 * Return: true jika permintaan perlu diproses selanjutnya, false jika tidak.
 */
static inline bool io_waitid_drop_issue_ref(struct io_kiocb *req)
{
	struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);
	struct io_waitid_async *iwa = req->async_data;

	if (!atomic_sub_return(1, &iw->refs))
		return false;

	req->io_task_work.func = io_waitid_cb;
	io_req_task_work_add(req);
	remove_wait_queue(iw->head, &iwa->wo.child_wait);
	return true;
}

/*
 * io_waitid_cb - Callback task_work untuk menyelesaikan waitid setelah bangun
 * @req: Permintaan io_uring yang terkait
 * @tw: Token task_work
 *
 * Callback ini dipicu oleh waitqueue atau oleh pembatalan untuk menyelesaikan waitid.
 * Jika perlu retry (misal karena -ERESTARTSYS), ia akan mendaftar ulang ke waitqueue.
 */
static void io_waitid_cb(struct io_kiocb *req, io_tw_token_t tw)
{
	struct io_waitid_async *iwa = req->async_data;
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	io_tw_lock(ctx, tw);

	ret = __do_wait(&iwa->wo);

	if (unlikely(ret == -ERESTARTSYS)) {
		struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);

		ret = -ECANCELED;
		if (!(atomic_read(&iw->refs) & IO_WAITID_CANCEL_FLAG)) {
			iw->head = &current->signal->wait_chldexit;
			add_wait_queue(iw->head, &iwa->wo.child_wait);
			ret = __do_wait(&iwa->wo);
			if (ret == -ERESTARTSYS) {
				io_waitid_drop_issue_ref(req);
				return;
			}

			remove_wait_queue(iw->head, &iwa->wo.child_wait);
		}
	}

	io_waitid_complete(req, ret);
	io_req_task_complete(req, tw);
}

/*
 * io_waitid_wait - Fungsi callback untuk entry di waitqueue waitid
 * @wait: Entry waitqueue
 * @mode: Mode bangun (tidak digunakan di sini)
 * @sync: Sinkronisasi (tidak digunakan)
 * @key: Proses yang menyebabkan bangun (task struct)
 *
 * Fungsi ini dipanggil saat ada anak proses yang berubah status.
 *
 * Return: 1 jika permintaan waitid diambil alih dan dijadwalkan, 0 jika diabaikan.
 */
static int io_waitid_wait(struct wait_queue_entry *wait, unsigned mode,
			  int sync, void *key)
{
	struct wait_opts *wo = container_of(wait, struct wait_opts, child_wait);
	struct io_waitid_async *iwa = container_of(wo, struct io_waitid_async, wo);
	struct io_kiocb *req = iwa->req;
	struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);
	struct task_struct *p = key;

	if (!pid_child_should_wake(wo, p))
		return 0;

	if (atomic_fetch_inc(&iw->refs) & IO_WAITID_REF_MASK)
		return 1;

	req->io_task_work.func = io_waitid_cb;
	io_req_task_work_add(req);
	list_del_init(&wait->entry);
	return 1;
}

/*
 * io_waitid_prep - Mempersiapkan permintaan waitid dari SQE
 * @req: Permintaan io_uring
 * @sqe: Entry dari submission queue
 *
 * Mem-parsing parameter dari SQE dan mengalokasikan data async.
 *
 * Return: 0 jika sukses, atau error code.
 */
int io_waitid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);
	struct io_waitid_async *iwa;

	if (sqe->addr || sqe->buf_index || sqe->addr3 || sqe->waitid_flags)
		return -EINVAL;

	iwa = io_uring_alloc_async_data(NULL, req);
	if (!unlikely(iwa))
		return -ENOMEM;

	iwa->req = req;

	iw->which = READ_ONCE(sqe->len);
	iw->upid = READ_ONCE(sqe->fd);
	iw->options = READ_ONCE(sqe->file_index);
	iw->infop = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	return 0;
}

/*
 * io_waitid - Fungsi utama untuk menangani permintaan waitid
 * @req: Permintaan io_uring
 * @issue_flags: Flag yang berkaitan dengan eksekusi permintaan
 *
 * Mendaftarkan ke waitqueue dan memanggil __do_wait() untuk melihat apakah
 * status anak proses sudah tersedia. Jika tidak, tunggu callback.
 *
 * Return: IOU_OK jika selesai langsung, IOU_ISSUE_SKIP_COMPLETE jika perlu ditunda.
 */
int io_waitid(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_waitid *iw = io_kiocb_to_cmd(req, struct io_waitid);
	struct io_waitid_async *iwa = req->async_data;
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	ret = kernel_waitid_prepare(&iwa->wo, iw->which, iw->upid, &iw->info,
					iw->options, NULL);
	if (ret)
		goto done;

	atomic_set(&iw->refs, 1);

	io_ring_submit_lock(ctx, issue_flags);
	hlist_add_head(&req->hash_node, &ctx->waitid_list);

	init_waitqueue_func_entry(&iwa->wo.child_wait, io_waitid_wait);
	iwa->wo.child_wait.private = req->tctx->task;
	iw->head = &current->signal->wait_chldexit;
	add_wait_queue(iw->head, &iwa->wo.child_wait);

	ret = __do_wait(&iwa->wo);
	if (ret == -ERESTARTSYS) {
		if (!io_waitid_drop_issue_ref(req)) {
			io_ring_submit_unlock(ctx, issue_flags);
			return IOU_ISSUE_SKIP_COMPLETE;
		}

		io_ring_submit_unlock(ctx, issue_flags);
		return IOU_ISSUE_SKIP_COMPLETE;
	}

	hlist_del_init(&req->hash_node);
	remove_wait_queue(iw->head, &iwa->wo.child_wait);
	ret = io_waitid_finish(req, ret);

	io_ring_submit_unlock(ctx, issue_flags);
done:
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

