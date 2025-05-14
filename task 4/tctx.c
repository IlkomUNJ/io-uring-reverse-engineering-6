// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/nospec.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "tctx.h"

/*
 * io_init_wq_offload - Inisialisasi workqueue khusus untuk offload io_uring
 * @ctx: Context io_uring
 * @task: Task yang terkait dengan context ini
 *
 * Jika hash_map workqueue belum tersedia, alokasikan dan inisialisasi.
 * Kemudian buat workqueue berdasarkan SQE entry dan jumlah CPU online.
 *
 * Return: Pointer ke workqueue jika sukses, atau ERR_PTR jika gagal.
 */
static struct io_wq *io_init_wq_offload(struct io_ring_ctx *ctx,
					struct task_struct *task)
{
	struct io_wq_hash *hash;
	struct io_wq_data data;
	unsigned int concurrency;

	mutex_lock(&ctx->uring_lock);
	hash = ctx->hash_map;
	if (!hash) {
		hash = kzalloc(sizeof(*hash), GFP_KERNEL);
		if (!hash) {
			mutex_unlock(&ctx->uring_lock);
			return ERR_PTR(-ENOMEM);
		}
		refcount_set(&hash->refs, 1);
		init_waitqueue_head(&hash->wait);
		ctx->hash_map = hash;
	}
	mutex_unlock(&ctx->uring_lock);

	data.hash = hash;
	data.task = task;
	data.free_work = io_wq_free_work;
	data.do_work = io_wq_submit_work;

	/* Gunakan minimum antara SQE entry dan 4 * jumlah CPU */
	concurrency = min(ctx->sq_entries, 4 * num_online_cpus());

	return io_wq_create(concurrency, &data);
}

/*
 * __io_uring_free - Membersihkan context io_uring dari task
 * @tsk: Task struct dari proses yang akan dibersihkan
 *
 * Fungsi ini membersihkan dan membebaskan io_uring_task dari task yang
 * dipanggil. Memastikan tidak ada node tersisa di xarray dan workqueue
 * telah di-nil-kan.
 */
void __io_uring_free(struct task_struct *tsk)
{
	struct io_uring_task *tctx = tsk->io_uring;
	struct io_tctx_node *node;
	unsigned long index;

	/* Validasi jika ada sisa node di xarray (error jika ada) */
	xa_for_each(&tctx->xa, index, node) {
		WARN_ON_ONCE(1);
		break;
	}
	WARN_ON_ONCE(tctx->io_wq);
	WARN_ON_ONCE(tctx->cached_refs);

	percpu_counter_destroy(&tctx->inflight);
	kfree(tctx);
	tsk->io_uring = NULL;
}

/*
 * io_uring_alloc_task_context - Mengalokasikan context task untuk io_uring
 * @task: Task struct untuk proses saat ini
 * @ctx: Context io_uring yang akan dihubungkan
 *
 * Alokasikan dan inisialisasi struktur io_uring_task untuk task.
 * Membangun workqueue dan inisialisasi struktur lainnya.
 *
 * Return: 0 jika berhasil, atau error code jika gagal.
 */
__cold int io_uring_alloc_task_context(struct task_struct *task,
				       struct io_ring_ctx *ctx)
{
	struct io_uring_task *tctx;
	int ret;

	tctx = kzalloc(sizeof(*tctx), GFP_KERNEL);
	if (unlikely(!tctx))
		return -ENOMEM;

	ret = percpu_counter_init(&tctx->inflight, 0, GFP_KERNEL);
	if (unlikely(ret)) {
		kfree(tctx);
		return ret;
	}

	tctx->io_wq = io_init_wq_offload(ctx, task);
	if (IS_ERR(tctx->io_wq)) {
		ret = PTR_ERR(tctx->io_wq);
		percpu_counter_destroy(&tctx->inflight);
		kfree(tctx);
		return ret;
	}

	tctx->task = task;
	xa_init(&tctx->xa);
	init_waitqueue_head(&tctx->wait);
	atomic_set(&tctx->in_cancel, 0);
	atomic_set(&tctx->inflight_tracked, 0);
	task->io_uring = tctx;
	init_llist_head(&tctx->task_list);
	init_task_work(&tctx->task_work, tctx_task_work);
	return 0;
}

/*
 * __io_uring_add_tctx_node - Tambahkan task context node ke context io_uring
 * @ctx: Context io_uring
 *
 * Fungsi ini menghubungkan task (current) ke context io_uring tertentu.
 * Jika belum ada tctx, maka akan dialokasikan.
 *
 * Return: 0 jika berhasil, atau error code jika gagal.
 */
int __io_uring_add_tctx_node(struct io_ring_ctx *ctx)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_tctx_node *node;
	int ret;

	if (unlikely(!tctx)) {
		ret = io_uring_alloc_task_context(current, ctx);
		if (unlikely(ret))
			return ret;

		tctx = current->io_uring;
		if (ctx->iowq_limits_set) {
			unsigned int limits[2] = { ctx->iowq_limits[0],
						   ctx->iowq_limits[1], };

			ret = io_wq_max_workers(tctx->io_wq, limits);
			if (ret)
				return ret;
		}
	}
	if (!xa_load(&tctx->xa, (unsigned long)ctx)) {
		node = kmalloc(sizeof(*node), GFP_KERNEL);
		if (!node)
			return -ENOMEM;
		node->ctx = ctx;
		node->task = current;

		ret = xa_err(xa_store(&tctx->xa, (unsigned long)ctx,
					node, GFP_KERNEL));
		if (ret) {
			kfree(node);
			return ret;
		}

		mutex_lock(&ctx->uring_lock);
		list_add(&node->ctx_node, &ctx->tctx_list);
		mutex_unlock(&ctx->uring_lock);
	}
	return 0;
}

/*
 * __io_uring_add_tctx_node_from_submit - Tambahkan tctx node saat submit SQE
 * @ctx: Context io_uring
 *
 * Memastikan bahwa task saat ini sesuai dengan SINGLE_ISSUER (jika aktif),
 * lalu tambahkan node dari submitter task.
 *
 * Return: 0 jika sukses, atau error code jika gagal.
 */
int __io_uring_add_tctx_node_from_submit(struct io_ring_ctx *ctx)
{
	int ret;

	if (ctx->flags & IORING_SETUP_SINGLE_ISSUER
	    && ctx->submitter_task != current)
		return -EEXIST;

	ret = __io_uring_add_tctx_node(ctx);
	if (ret)
		return ret;

	current->io_uring->last = ctx;
	return 0;
}

/*
 * io_uring_del_tctx_node - Menghapus hubungan antara task dan io_uring ctx
 * @index: Index context dalam xarray tctx
 *
 * Melepas node yang merepresentasikan hubungan task dengan context tertentu.
 * Ini dilakukan saat context tidak lagi digunakan oleh task tersebut.
 */
__cold void io_uring_del_tctx_node(unsigned long index)
{
	struct io_uring_task *tctx = current->io_uring;
	struct io_tctx_node *node;

	if (!tctx)
		return;
	node = xa_erase(&tctx->xa, index);
	if (!node)
		return;

	WARN_ON_ONCE(current != node->task);
	WARN_ON_ONCE(list_empty(&node->ctx_node));

	mutex_lock(&node->ctx->uring_lock);
	list_del(&node->ctx_node);
	mutex_unlock(&node->ctx->uring_lock);

	if (tctx->last == node->ctx)
		tctx->last = NULL;
	kfree(node);
}

/*
 * io_uring_clean_tctx - Membersihkan seluruh node dan workqueue milik tctx
 * @tctx: Pointer ke struktur io_uring_task milik task saat ini
 *
 * Menghapus semua io_tctx_node yang terdaftar di xarray dan
 * melepaskan workqueue yang terkait. Dipanggil saat proses/thread
 * keluar dan io_uring dibersihkan dari task-nya.
 */
__cold void io_uring_clean_tctx(struct io_uring_task *tctx)
{
	struct io_wq *wq = tctx->io_wq;
	struct io_tctx_node *node;
	unsigned long index;

	xa_for_each(&tctx->xa, index, node) {
		io_uring_del_tctx_node(index);
		cond_resched();
	}
	if (wq) {
		/*
		 * Harus dipanggil setelah io_uring_del_tctx_node()
		 * untuk menghindari race dengan io_uring_try_cancel_iowq().
		 */
		io_wq_put_and_exit(wq);
		tctx->io_wq = NULL;
	}
}

/*
 * io_uring_unreg_ringfd - Menghapus semua ring file descriptor yang terdaftar
 *
 * Membersihkan dan melepaskan referensi ke semua file descriptor
 * yang terdaftar sebagai ringfd dalam io_uring_task.
 */
void io_uring_unreg_ringfd(void)
{
	struct io_uring_task *tctx = current->io_uring;
	int i;

	for (i = 0; i < IO_RINGFD_REG_MAX; i++) {
		if (tctx->registered_rings[i]) {
			fput(tctx->registered_rings[i]);
			tctx->registered_rings[i] = NULL;
		}
	}
}

/*
 * io_ring_add_registered_file - Menambahkan file ke slot ringfd yang kosong
 * @tctx: io_uring_task milik task saat ini
 * @file: File pointer yang ingin didaftarkan
 * @start: Indeks awal pencarian slot kosong
 * @end: Indeks akhir pencarian slot kosong
 *
 * Mencari slot kosong di array registered_rings dan menyimpan
 * referensi file ke sana.
 *
 * Return: Offset slot jika berhasil, atau -EBUSY jika semua slot penuh.
 */
int io_ring_add_registered_file(struct io_uring_task *tctx, struct file *file,
				     int start, int end)
{
	int offset;
	for (offset = start; offset < end; offset++) {
		offset = array_index_nospec(offset, IO_RINGFD_REG_MAX);
		if (tctx->registered_rings[offset])
			continue;

		tctx->registered_rings[offset] = file;
		return offset;
	}
	return -EBUSY;
}

/*
 * io_ring_add_registered_fd - Ambil file dari fd dan daftarkan sebagai ringfd
 * @tctx: io_uring_task milik task saat ini
 * @fd: File descriptor user yang ingin didaftarkan
 * @start: Indeks awal pencarian slot kosong
 * @end: Indeks akhir pencarian slot kosong
 *
 * Validasi file descriptor, ambil file, dan simpan di array registered_rings.
 *
 * Return: Offset slot jika sukses, atau kode error jika gagal.
 */
static int io_ring_add_registered_fd(struct io_uring_task *tctx, int fd,
				     int start, int end)
{
	struct file *file;
	int offset;

	file = fget(fd);
	if (!file) {
		return -EBADF;
	} else if (!io_is_uring_fops(file)) {
		fput(file);
		return -EOPNOTSUPP;
	}
	offset = io_ring_add_registered_file(tctx, file, start, end);
	if (offset < 0)
		fput(file);
	return offset;
}

/*
 * io_ringfd_register - Mendaftarkan file descriptor io_uring ke ringfd slot
 * @ctx: Context io_uring yang aktif
 * @__arg: Pointer user ke array io_uring_rsrc_update
 * @nr_args: Jumlah entry yang akan didaftarkan
 *
 * Fungsi ini memungkinkan aplikasi mendaftarkan io_uring milik thread lain
 * agar tidak perlu melakukan fdget/fdput setiap kali pemanggilan
 * io_uring_enter(). Jika offset == -1U, maka akan mencari slot kosong otomatis.
 *
 * Return: Jumlah entry yang sukses didaftarkan, atau kode error jika gagal.
 */
int io_ringfd_register(struct io_ring_ctx *ctx, void __user *__arg,
		       unsigned nr_args)
{
	struct io_uring_rsrc_update __user *arg = __arg;
	struct io_uring_rsrc_update reg;
	struct io_uring_task *tctx;
	int ret, i;

	if (!nr_args || nr_args > IO_RINGFD_REG_MAX)
		return -EINVAL;

	mutex_unlock(&ctx->uring_lock);
	ret = __io_uring_add_tctx_node(ctx);
	mutex_lock(&ctx->uring_lock);
	if (ret)
		return ret;

	tctx = current->io_uring;
	for (i = 0; i < nr_args; i++) {
		int start, end;

		if (copy_from_user(&reg, &arg[i], sizeof(reg))) {
			ret = -EFAULT;
			break;
		}

		if (reg.resv) {
			ret = -EINVAL;
			break;
		}

		if (reg.offset == -1U) {
			start = 0;
			end = IO_RINGFD_REG_MAX;
		} else {
			if (reg.offset >= IO_RINGFD_REG_MAX) {
				ret = -EINVAL;
				break;
			}
			start = reg.offset;
			end = start + 1;
		}

		ret = io_ring_add_registered_fd(tctx, reg.data, start, end);
		if (ret < 0)
			break;

		reg.offset = ret;
		if (copy_to_user(&arg[i], &reg, sizeof(reg))) {
			fput(tctx->registered_rings[reg.offset]);
			tctx->registered_rings[reg.offset] = NULL;
			ret = -EFAULT;
			break;
		}
	}

	return i ? i : ret;
}

/*
 * io_ringfd_unregister - Menghapus ringfd yang sebelumnya terdaftar
 * @ctx: Context io_uring yang aktif
 * @__arg: Pointer user ke array io_uring_rsrc_update
 * @nr_args: Jumlah entry yang akan dihapus
 *
 * Fungsi ini menghapus file descriptor dari array registered_rings
 * berdasarkan indeks yang diberikan oleh user.
 *
 * Return: Jumlah entry yang berhasil dihapus, atau error jika tidak ada.
 */
int io_ringfd_unregister(struct io_ring_ctx *ctx, void __user *__arg,
			 unsigned nr_args)
{
	struct io_uring_rsrc_update __user *arg = __arg;
	struct io_uring_task *tctx = current->io_uring;
	struct io_uring_rsrc_update reg;
	int ret = 0, i;

	if (!nr_args || nr_args > IO_RINGFD_REG_MAX)
		return -EINVAL;
	if (!tctx)
		return 0;

	for (i = 0; i < nr_args; i++) {
		if (copy_from_user(&reg, &arg[i], sizeof(reg))) {
			ret = -EFAULT;
			break;
		}
		if (reg.resv || reg.data || reg.offset >= IO_RINGFD_REG_MAX) {
			ret = -EINVAL;
			break;
		}

		reg.offset = array_index_nospec(reg.offset, IO_RINGFD_REG_MAX);
		if (tctx->registered_rings[reg.offset]) {
			fput(tctx->registered_rings[reg.offset]);
			tctx->registered_rings[reg.offset] = NULL;
		}
	}

	return i ? i : ret;
}

