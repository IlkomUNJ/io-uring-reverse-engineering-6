// SPDX-License-Identifier: GPL-2.0

// Struktur untuk menyimpan data yang terkait dengan operasi timeout dalam I/O menggunakan io_uring.
struct io_timeout_data {
	struct io_kiocb			*req;        // Pointer ke kontrol blok I/O yang terkait dengan timeout.
	struct hrtimer			timer;      // Timer yang digunakan untuk menandai waktu habis.
	struct timespec64		ts;         // Waktu yang akan diatur untuk timeout.
	enum hrtimer_mode		mode;       // Mode timer, apakah timer akan di-reset atau dihentikan.
	u32				flags;      // Flag tambahan untuk mengatur perilaku timeout.
};

// Fungsi untuk menonaktifkan (disarm) timeout yang terhubung (linked) pada `req`.
struct io_kiocb *__io_disarm_linked_timeout(struct io_kiocb *req,
					    struct io_kiocb *link);

// Fungsi inline untuk menonaktifkan timeout yang terhubung pada `req`.
// Jika ada tautan (`link`) dan opcode adalah IORING_OP_LINK_TIMEOUT, maka `__io_disarm_linked_timeout` dipanggil.
static inline struct io_kiocb *io_disarm_linked_timeout(struct io_kiocb *req)
{
	struct io_kiocb *link = req->link;

	if (link && link->opcode == IORING_OP_LINK_TIMEOUT)
		return __io_disarm_linked_timeout(req, link);

	return NULL;
}

// Fungsi untuk mengosongkan semua timeout dalam konteks I/O ring.
__cold void io_flush_timeouts(struct io_ring_ctx *ctx);

// Fungsi untuk membatalkan timeout, digunakan dalam operasi pembatalan I/O.
int io_timeout_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd);

// Fungsi untuk membunuh semua timeout dalam konteks I/O ring atau membatalkan timeout jika `cancel_all` disetel.
__cold bool io_kill_timeouts(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			     bool cancel_all);

// Fungsi untuk mengantri timeout yang terhubung dalam queue I/O.
void io_queue_linked_timeout(struct io_kiocb *req);

// Fungsi untuk menonaktifkan timeout berikutnya setelah `req`.
void io_disarm_next(struct io_kiocb *req);

// Fungsi untuk mempersiapkan operasi timeout dalam I/O menggunakan io_uring.
int io_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi link timeout, menghubungkan operasi timeout dengan operasi lain dalam I/O ring.
int io_link_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mengeksekusi operasi timeout dalam I/O menggunakan io_uring.
int io_timeout(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk mempersiapkan penghapusan operasi timeout dari I/O ring.
int io_timeout_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk menghapus operasi timeout dari I/O ring.
int io_timeout_remove(struct io_kiocb *req, unsigned int issue_flags);

