/* SPDX-License-Identifier: GPL-2.0 */

#ifndef IOU_NAPI_H
#define IOU_NAPI_H

#include <linux/kernel.h>
#include <linux/io_uring.h>
#include <net/busy_poll.h>

#ifdef CONFIG_NET_RX_BUSY_POLL

/* Menginisialisasi dukungan NAPI pada context io_uring. */
void io_napi_init(struct io_ring_ctx *ctx);

/* Membebaskan resource yang berkaitan dengan NAPI dalam context. */
void io_napi_free(struct io_ring_ctx *ctx);

/* Mendaftarkan NAPI ID dari userspace ke context io_uring. */
int io_register_napi(struct io_ring_ctx *ctx, void __user *arg);

/* Menghapus registrasi NAPI ID dari context io_uring. */
int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg);

/* Menambahkan NAPI ID ke context dari kernel (digunakan internal). */
int __io_napi_add_id(struct io_ring_ctx *ctx, unsigned int napi_id);

/* Melakukan busy-polling menggunakan NAPI pada context tertentu. */
void __io_napi_busy_loop(struct io_ring_ctx *ctx, struct io_wait_queue *iowq);

/* Melakukan busy-polling saat SQPOLL aktif dan NAPI digunakan. */
int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx);

/* Mengecek apakah context memiliki entri NAPI terdaftar. */
static inline bool io_napi(struct io_ring_ctx *ctx)
{
	return !list_empty(&ctx->napi_list);
}

/* Wrapper untuk __io_napi_busy_loop jika context memiliki NAPI. */
static inline void io_napi_busy_loop(struct io_ring_ctx *ctx,
				     struct io_wait_queue *iowq)
{
	if (!io_napi(ctx))
		return;
	__io_napi_busy_loop(ctx, iowq);
}

/*
 * io_napi_add() - Menambahkan NAPI ID dari request ke daftar polling
 * @req: pointer ke permintaan io_kiocb
 *
 * Jika mode pelacakan NAPI adalah dinamis, maka NAPI ID dari socket
 * akan diambil dan dimasukkan ke dalam daftar NAPI pada context.
 */
static inline void io_napi_add(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct socket *sock;

	if (READ_ONCE(ctx->napi_track_mode) != IO_URING_NAPI_TRACKING_DYNAMIC)
		return;

	sock = sock_from_file(req->file);
	if (sock && sock->sk)
		__io_napi_add_id(ctx, READ_ONCE(sock->sk->sk_napi_id));
}

#else /* CONFIG_NET_RX_BUSY_POLL not defined */

/* Stub kosong jika NAPI tidak didukung. */
static inline void io_napi_init(struct io_ring_ctx *ctx) { }

/* Stub kosong jika NAPI tidak didukung. */
static inline void io_napi_free(struct io_ring_ctx *ctx) { }

/* Return error karena tidak didukung. */
static inline int io_register_napi(struct io_ring_ctx *ctx, void __user *arg)
{
	return -EOPNOTSUPP;
}

/* Return error karena tidak didukung. */
static inline int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg)
{
	return -EOPNOTSUPP;
}

/* Return false karena tidak ada dukungan NAPI. */
static inline bool io_napi(struct io_ring_ctx *ctx)
{
	return false;
}

/* Stub kosong jika NAPI tidak didukung. */
static inline void io_napi_add(struct io_kiocb *req) { }

/* Stub kosong jika NAPI tidak didukung. */
static inline void io_napi_busy_loop(struct io_ring_ctx *ctx,
				     struct io_wait_queue *iowq) { }

/* Return 0 karena tidak ada polling NAPI yang dijalankan. */
static inline int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx)
{
	return 0;
}
#endif /* CONFIG_NET_RX_BUSY_POLL */

#endif /* IOU_NAPI_H */

