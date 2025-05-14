// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_ZC_RX_H
#define IOU_ZC_RX_H

#include <linux/io_uring_types.h>   // Header untuk struktur dan tipe data terkait io_uring
#include <linux/socket.h>           // Header untuk tipe data dan fungsi terkait socket
#include <net/page_pool/types.h>    // Header untuk tipe data terkait page pool di jaringan
#include <net/net_trackers.h>       // Header untuk melacak status jaringan

// Struktur yang mewakili area Zero Copy Receive (ZCRX)
struct io_zcrx_area {
	struct net_iov_area	nia;          // Area untuk Input/Output Vectors (IOV)
	struct io_zcrx_ifq	*ifq;          // Pointer ke input queue ZCRX
	atomic_t		*user_refs;    // Referensi untuk melacak penggunaan area ini oleh pengguna

	bool			is_mapped;     // Menunjukkan apakah area ini dipetakan di memori
	u16			area_id;       // ID untuk area ZCRX ini
	struct page		**pages;       // Pointer ke array halaman yang terkait dengan area ini

	// freelist untuk mengelola halaman yang tidak digunakan
	spinlock_t		freelist_lock ____cacheline_aligned_in_smp;  // Spinlock untuk sinkronisasi akses freelist
	u32			free_count;    // Jumlah halaman yang ada di freelist
	u32			*freelist;     // Pointer ke array freelist yang berisi halaman yang dapat digunakan kembali
};

// Struktur yang mewakili input queue ZCRX
struct io_zcrx_ifq {
	struct io_ring_ctx		*ctx;          // Pointer ke konteks io_uring
	struct io_zcrx_area		*area;         // Pointer ke area ZCRX yang terkait

	struct io_uring			*rq_ring;      // Pointer ke ring buffer uring untuk permintaan
	struct io_uring_zcrx_rqe	*rqes;         // Pointer ke array ring queue entries (RQE)
	u32				rq_entries;    // Jumlah entri dalam ring queue
	u32				cached_rq_head; // Indeks untuk head dari ring queue yang dicache
	spinlock_t			rq_lock;       // Spinlock untuk sinkronisasi akses ring queue

	u32				if_rxq;        // RX Queue ID untuk interface
	struct device			*dev;          // Pointer ke perangkat yang terkait
	struct net_device		*netdev;       // Pointer ke perangkat jaringan yang terkait
	netdevice_tracker		netdev_tracker; // Tracker perangkat jaringan
	spinlock_t			lock;          // Spinlock untuk sinkronisasi akses internal
};

// Header-fitur spesifik yang hanya disertakan jika CONFIG_IO_URING_ZCRX didefinisikan
#if defined(CONFIG_IO_URING_ZCRX)
// Fungsi untuk mendaftarkan ZCRX input queue (IFQ)
int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
			 struct io_uring_zcrx_ifq_reg __user *arg);

// Fungsi untuk membatalkan pendaftaran ZCRX IFQs
void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx);

// Fungsi untuk mematikan ZCRX IFQs
void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx);

// Fungsi untuk menerima data Zero Copy (ZCRX) pada input queue ZCRX
int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
		 struct socket *sock, unsigned int flags,
		 unsigned issue_flags, unsigned int *len);
#else
// Jika CONFIG_IO_URING_ZCRX tidak didefinisikan, semua fungsi terkait akan menjadi inline dan tidak mendukung ZCRX
static inline int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
					struct io_uring_zcrx_ifq_reg __user *arg)
{
	return -EOPNOTSUPP; // Fungsi tidak didukung
}
static inline void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx)
{
}
static inline void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx)
{
}
static inline int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
			       struct socket *sock, unsigned int flags,
			       unsigned issue_flags, unsigned int *len)
{
	return -EOPNOTSUPP; // Fungsi tidak didukung
}
#endif

// Fungsi untuk menerima data Zero Copy secara umum
int io_recvzc(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk mempersiapkan penerimaan Zero Copy
int io_recvzc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

#endif

