// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring_types.h>

#define IO_POLL_ALLOC_CACHE_MAX 32  // Maksimum jumlah cache untuk alokasi polling

// Status polling
enum {
	IO_APOLL_OK,       // Polling berhasil
	IO_APOLL_ABORTED,  // Polling dibatalkan
	IO_APOLL_READY     // Polling siap untuk dieksekusi
};

// Struktur untuk polling I/O
struct io_poll {
	struct file			*file;   // File yang digunakan dalam polling
	struct wait_queue_head		*head;   // Head dari antrian tunggu untuk polling
	__poll_t			events;  // Jenis event yang dipantau
	int				retries; // Jumlah percobaan polling
	struct wait_queue_entry		wait;   // Entri untuk antrian tunggu
};

// Struktur untuk polling asinkron
struct async_poll {
	struct io_poll		poll;          // Polling utama
	struct io_poll		*double_poll;  // Polling tambahan untuk multishot
};

/*
 * Fungsi untuk mencoba ulang polling pada mode multishot.
 * Harus dipanggil hanya di dalam IO_URING_F_MULTISHOT atau ketika kita
 * sudah "memiliki" permintaan polling ini.
 */
static inline void io_poll_multishot_retry(struct io_kiocb *req)
{
	atomic_inc(&req->poll_refs);  // Menambah referensi polling untuk multishot
}

// Fungsi untuk menyiapkan polling
int io_poll_add_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk menambahkan polling
int io_poll_add(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk menyiapkan penghapusan polling
int io_poll_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk menghapus polling
int io_poll_remove(struct io_kiocb *req, unsigned int issue_flags);

// Struktur data pembatalan I/O
struct io_cancel_data;

// Fungsi untuk membatalkan polling
int io_poll_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		   unsigned issue_flags);

// Fungsi untuk menangani polling ketika sudah siap
int io_arm_poll_handler(struct io_kiocb *req, unsigned issue_flags);

// Fungsi untuk menghapus semua polling terkait
bool io_poll_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			bool cancel_all);

// Fungsi untuk menjalankan polling pada task tertentu
void io_poll_task_func(struct io_kiocb *req, io_tw_token_t tw);

