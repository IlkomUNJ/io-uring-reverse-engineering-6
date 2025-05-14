// SPDX-License-Identifier: GPL-2.0

#include <linux/net.h>       // Header untuk operasi jaringan
#include <linux/uio.h>       // Header untuk operasi I/O dengan buffer pengguna
#include <net/sock.h>        // Header untuk operasi terkait soket
#include <linux/nospec.h>    // Header untuk pengamanan dari spekulasi kode

#include "rsrc.h"            // Header eksternal untuk mengelola sumber daya

// Flag yang digunakan untuk menentukan karakteristik pengelolaan fragmen zerocopy
#define IO_NOTIF_UBUF_FLAGS  (SKBFL_ZEROCOPY_FRAG | SKBFL_DONT_ORPHAN)

// Batch pengiriman splice (untuk operasi pemrosesan data jaringan)
#define IO_NOTIF_SPLICE_BATCH 32

/*
 * Struktur io_notif_data yang digunakan untuk mengelola data notifikasi I/O.
 * Struktur ini mencakup informasi tentang file terkait, informasi buffer pengguna,
 * dan daftar notifikasi untuk pengelolaan memori dan status zerocopy.
 */
struct io_notif_data {
	struct file		*file;       // Pointer ke file terkait
	struct ubuf_info	uarg;       // Struktur informasi buffer pengguna

	struct io_notif_data	*next;      // Pointer ke notifikasi berikutnya dalam daftar
	struct io_notif_data	*head;      // Pointer ke kepala daftar notifikasi

	unsigned		account_pages; // Jumlah halaman yang terhitung untuk notifikasi ini
	bool			zc_report;    // Menandakan apakah laporan zerocopy diperlukan
	bool			zc_used;      // Menandakan apakah zerocopy digunakan
	bool			zc_copied;    // Menandakan apakah data zerocopy telah disalin
};

/*
 * Fungsi untuk mengalokasikan struktur io_kiocb untuk notifikasi I/O.
 */
struct io_kiocb *io_alloc_notif(struct io_ring_ctx *ctx);

/*
 * Fungsi untuk menyelesaikan pengiriman buffer pengguna (ubuf) setelah selesai
 * dikirim melalui soket.
 */
void io_tx_ubuf_complete(struct sk_buff *skb, struct ubuf_info *uarg, bool success);

/*
 * Konversi notifikasi I/O (kiocb) ke struktur io_notif_data terkait.
 */
static inline struct io_notif_data *io_notif_to_data(struct io_kiocb *notif)
{
	return io_kiocb_to_cmd(notif, struct io_notif_data);
}

/*
 * Fungsi untuk menyelesaikan pengelolaan notifikasi I/O, harus dipanggil
 * saat sudah memegang lock pada uring.
 */
static inline void io_notif_flush(struct io_kiocb *notif)
	__must_hold(&notif->ctx->uring_lock)
{
	struct io_notif_data *nd = io_notif_to_data(notif);

	// Menyelesaikan buffer pengguna yang terkait dengan notifikasi ini
	io_tx_ubuf_complete(NULL, &nd->uarg, true);
}

/*
 * Fungsi untuk menghitung memori yang digunakan oleh notifikasi I/O dan
 * melakukan pengelolaan memori untuknya.
 */
static inline int io_notif_account_mem(struct io_kiocb *notif, unsigned len)
{
	struct io_ring_ctx *ctx = notif->ctx;
	struct io_notif_data *nd = io_notif_to_data(notif);
	unsigned nr_pages = (len >> PAGE_SHIFT) + 2; // Menghitung jumlah halaman yang digunakan
	int ret;

	if (ctx->user) {
		// Menghitung dan mengalokasikan memori yang digunakan oleh pengguna
		ret = __io_account_mem(ctx->user, nr_pages);
		if (ret)
			return ret;
		nd->account_pages += nr_pages;
	}
	return 0;
}

