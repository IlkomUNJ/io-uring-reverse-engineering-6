// SPDX-License-Identifier: GPL-2.0

// Mengimpor file header yang berkaitan dengan proses exit pada kernel.
#include "../kernel/exit.h"

// Struktur untuk menangani operasi waitid secara asinkron.
// Menyimpan informasi tentang request (req) dan opsi tunggu (wo).
struct io_waitid_async {
	struct io_kiocb *req;  // Pointer ke objek io_kiocb yang mewakili permintaan I/O.
	struct wait_opts wo;   // Struktur yang berisi opsi untuk menunggu.
};

// Fungsi ini mempersiapkan permintaan untuk operasi waitid menggunakan io_uring.
// Memastikan bahwa operasi yang berkaitan dengan menunggu ID (seperti proses atau thread) dipersiapkan dengan benar.
int io_waitid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi ini menjalankan operasi waitid yang telah dipersiapkan sebelumnya.
// Ini merupakan fungsi inti untuk melakukan operasi menunggu ID (misalnya, menunggu proses selesai) di dalam io_uring.
int io_waitid(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi ini menangani pembatalan operasi waitid yang sedang berlangsung.
// Menggunakan konteks cancel untuk membatalkan operasi menunggu ID yang mungkin masih berjalan.
int io_waitid_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags);

// Fungsi ini menghapus semua operasi waitid yang terkait dengan suatu konteks tertentu.
// Berguna untuk membersihkan operasi waitid yang tertunda, dengan opsi untuk membatalkan semuanya.
bool io_waitid_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  bool cancel_all);

