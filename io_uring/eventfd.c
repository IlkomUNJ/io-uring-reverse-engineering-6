// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/eventfd.h>
#include <linux/eventpoll.h>
#include <linux/io_uring.h>
#include <linux/io_uring_types.h>

#include "io-wq.h"
#include "eventfd.h"

// Struktur untuk menangani eventfd yang digunakan oleh io_uring
struct io_ev_fd {
	struct eventfd_ctx	*cq_ev_fd;  // Context untuk eventfd
	unsigned int		eventfd_async; // Flag untuk eventfd asynchronous
	/* protected by ->completion_lock */
	unsigned		last_cq_tail; // Menyimpan tail CQ terakhir
	refcount_t		refs; // Reference count untuk manajemen memori
	atomic_t		ops;  // Operasi atomik
	struct rcu_head		rcu;  // Untuk pembersihan dengan RCU
};

enum {
	IO_EVENTFD_OP_SIGNAL_BIT,  // Bit untuk operasi sinyal pada eventfd
};

// Fungsi untuk membebaskan eventfd ketika tidak lagi digunakan
static void io_eventfd_free(struct rcu_head *rcu)
{
	struct io_ev_fd *ev_fd = container_of(rcu, struct io_ev_fd, rcu);

	eventfd_ctx_put(ev_fd->cq_ev_fd);  // Membebaskan context eventfd
	kfree(ev_fd);  // Membebaskan memori struktur io_ev_fd
}

// Fungsi untuk mengurangi reference count dari io_ev_fd
static void io_eventfd_put(struct io_ev_fd *ev_fd)
{
	if (refcount_dec_and_test(&ev_fd->refs))  // Mengecek apakah reference count mencapai 0
		call_rcu(&ev_fd->rcu, io_eventfd_free);  // Menjadwalkan pembebasan dengan RCU
}

// Fungsi untuk memicu sinyal pada eventfd
static void io_eventfd_do_signal(struct rcu_head *rcu)
{
	struct io_ev_fd *ev_fd = container_of(rcu, struct io_ev_fd, rcu);

	eventfd_signal_mask(ev_fd->cq_ev_fd, EPOLL_URING_WAKE);  // Mengirim sinyal
	io_eventfd_put(ev_fd);  // Membebaskan referensi setelah sinyal dikirim
}

// Fungsi untuk melepaskan eventfd dengan memeriksa apakah referensi perlu dikurangi
static void io_eventfd_release(struct io_ev_fd *ev_fd, bool put_ref)
{
	if (put_ref)
		io_eventfd_put(ev_fd);  // Mengurangi referensi jika diperlukan
	rcu_read_unlock();  // Menutup RCU read lock
}

/*
 * Mengembalikan true jika pemanggil harus melepaskan referensi ev_fd,
 * false jika tidak.
 */
static bool __io_eventfd_signal(struct io_ev_fd *ev_fd)
{
	if (eventfd_signal_allowed()) {  // Mengecek apakah sinyal diizinkan
		eventfd_signal_mask(ev_fd->cq_ev_fd, EPOLL_URING_WAKE);  // Kirim sinyal
		return true;
	}
	// Jika sinyal belum diatur, jadwalkan sinyal menggunakan RCU
	if (!atomic_fetch_or(BIT(IO_EVENTFD_OP_SIGNAL_BIT), &ev_fd->ops)) {
		call_rcu_hurry(&ev_fd->rcu, io_eventfd_do_signal);
		return false;
	}
	return true;
}

/*
 * Memicu eventfd jika eventfd_async tidak diset, atau jika diset dan pemanggil adalah pekerja async.
 * Mengembalikan false jika ev_fd tidak valid.
 */
static bool io_eventfd_trigger(struct io_ev_fd *ev_fd)
{
	if (ev_fd)
		return !ev_fd->eventfd_async || io_wq_current_is_worker();  // Memeriksa kondisi trigger
	return false;
}

/*
 * Mengambil referensi ev_fd dan mengunci RCU read lock.
 * Mengembalikan ev_fd jika sukses, NULL jika gagal.
 */
static struct io_ev_fd *io_eventfd_grab(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	if (READ_ONCE(ctx->rings->cq_flags) & IORING_CQ_EVENTFD_DISABLED)
		return NULL;  // Mengembalikan NULL jika eventfd dinonaktifkan

	rcu_read_lock();  // Mengunci RCU untuk membaca ctx->io_ev_fd

	// Mengambil referensi dari ctx->io_ev_fd dengan RCU
	ev_fd = rcu_dereference(ctx->io_ev_fd);

	// Mengecek ulang setelah RCU lock
	if (io_eventfd_trigger(ev_fd) && refcount_inc_not_zero(&ev_fd->refs))
		return ev_fd;

	rcu_read_unlock();  // Membuka RCU read lock jika gagal
	return NULL;
}

// Fungsi untuk memicu sinyal pada eventfd
void io_eventfd_signal(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	ev_fd = io_eventfd_grab(ctx);  // Mengambil referensi ev_fd
	if (ev_fd)
		io_eventfd_release(ev_fd, __io_eventfd_signal(ev_fd));  // Memicu sinyal
}

// Fungsi untuk flush sinyal pada eventfd
void io_eventfd_flush_signal(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	ev_fd = io_eventfd_grab(ctx);  // Mengambil referensi ev_fd
	if (ev_fd) {
		bool skip, put_ref = true;

		// Mengecek apakah CQ tail telah berubah
		spin_lock(&ctx->completion_lock);
		skip = ctx->cached_cq_tail == ev_fd->last_cq_tail;
		ev_fd->last_cq_tail = ctx->cached_cq_tail;
		spin_unlock(&ctx->completion_lock);

		if (!skip)  // Memicu sinyal hanya jika CQ tail berubah
			put_ref = __io_eventfd_signal(ev_fd);

		io_eventfd_release(ev_fd, put_ref);  // Melepaskan ev_fd
	}
}

// Fungsi untuk mendaftarkan eventfd dengan io_uring
int io_eventfd_register(struct io_ring_ctx *ctx, void __user *arg,
			unsigned int eventfd_async)
{
	struct io_ev_fd *ev_fd;
	__s32 __user *fds = arg;
	int fd;

	// Mengecek apakah eventfd sudah terdaftar
	ev_fd = rcu_dereference_protected(ctx->io_ev_fd,
					lockdep_is_held(&ctx->uring_lock));
	if (ev_fd)
		return -EBUSY;  // Jika sudah terdaftar, kembalikan error

	if (copy_from_user(&fd, fds, sizeof(*fds)))  // Menyalin file descriptor dari pengguna
		return -EFAULT;

	// Alokasi memori untuk io_ev_fd
	ev_fd = kmalloc(sizeof(*ev_fd), GFP_KERNEL);
	if (!ev_fd)
		return -ENOMEM;  // Jika alokasi gagal, kembalikan error

	// Mendapatkan context eventfd dari file descriptor
	ev_fd->cq_ev_fd = eventfd_ctx_fdget(fd);
	if (IS_ERR(ev_fd->cq_ev_fd)) {
		int ret = PTR_ERR(ev_fd->cq_ev_fd);

		kfree(ev_fd);  // Membebaskan memori jika gagal
		return ret;
	}

	// Menyimpan status tail CQ terakhir
	spin_lock(&ctx->completion_lock);
	ev_fd->last_cq_tail = ctx->cached_cq_tail;
	spin_unlock(&ctx->completion_lock);

	ev_fd->eventfd_async = eventfd_async;
	ctx->has_evfd = true;  // Menandai bahwa eventfd telah didaftarkan
	refcount_set(&ev_fd->refs, 1);  // Mengatur refcount
	atomic_set(&ev_fd->ops, 0);  // Mengatur operasi atomik
	rcu_assign_pointer(ctx->io_ev_fd, ev_fd);  // Menyimpan eventfd dalam konteks
	return 0;
}

// Fungsi untuk membatalkan pendaftaran eventfd
int io_eventfd_unregister(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	ev_fd = rcu_dereference_protected(ctx->io_ev_fd,
					lockdep_is_held(&ctx->uring_lock));
	if (ev_fd) {
		ctx->has_evfd = false;
		rcu_assign_pointer(ctx->io_ev_fd, NULL);  // Melepaskan eventfd
		io_eventfd_put(ev_fd);  // Mengurangi refcount dan membebaskan memori
		return 0;
	}

	return -ENXIO;  // Mengembalikan error jika tidak ada eventfd yang terdaftar
}

